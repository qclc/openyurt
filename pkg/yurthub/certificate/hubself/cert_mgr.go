/*
Copyright 2020 The OpenYurt Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hubself

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/openyurtio/openyurt/cmd/yurthub/app/config"
	"github.com/openyurtio/openyurt/pkg/projectinfo"
	hubcert "github.com/openyurtio/openyurt/pkg/yurthub/certificate"
	"github.com/openyurtio/openyurt/pkg/yurthub/certificate/interfaces"
	"github.com/openyurtio/openyurt/pkg/yurthub/storage"
	"github.com/openyurtio/openyurt/pkg/yurthub/storage/disk"
	"github.com/openyurtio/openyurt/pkg/yurthub/util"

	certificates "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	certificatesclient "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate"
	"k8s.io/klog"
)

const (
	CertificateManagerName  = "hubself"
	HubName                 = "yurthub"
	HubRootDir              = "/var/lib/"
	HubPkiDirName           = "pki"
	HubCaFileName           = "ca.crt"
	HubConfigFileName       = "%s.conf"
	BootstrapConfigFileName = "bootstrap-hub.conf"
	BootstrapUser           = "token-bootstrap-client"
	DefaultClusterName      = "kubernetes"
	ClusterInfoName         = "cluster-info"
	KubeconfigName          = "kubeconfig"
)

// Register registers a YurtCertificateManager
func Register(cmr *hubcert.CertificateManagerRegistry) {
	cmr.Register(CertificateManagerName, func(cfg *config.YurtHubConfiguration) (interfaces.YurtCertificateManager, error) {
		return NewYurtHubCertManager(cfg)
	})
}

type yurtHubCertManager struct {
	remoteServers        []*url.URL
	bootstrapConfStore   storage.Store
	hubClientCertManager certificate.Manager
	hubClientCertPath    string
	joinToken            string
	caFile               string
	nodeName             string
	rootDir              string
	hubName              string
	dialer               *util.Dialer
	stopCh               chan struct{}
}

// NewYurtHubCertManager new a YurtCertificateManager instance
func NewYurtHubCertManager(cfg *config.YurtHubConfiguration) (interfaces.YurtCertificateManager, error) {
	if cfg == nil || len(cfg.NodeName) == 0 || len(cfg.RemoteServers) == 0 {
		return nil, fmt.Errorf("hub agent configuration is invalid, could not new hub agent cert manager")
	}

	hubName := projectinfo.GetHubName()
	if len(hubName) == 0 {
		hubName = HubName
	}

	rootDir := cfg.RootDir
	if len(rootDir) == 0 {
		rootDir = filepath.Join(HubRootDir, hubName)
	}

	ycm := &yurtHubCertManager{
		remoteServers: cfg.RemoteServers,
		nodeName:      cfg.NodeName,
		joinToken:     cfg.JoinToken,
		rootDir:       rootDir,
		hubName:       hubName,
		dialer:        util.NewDialer("hub certificate manager"),
		stopCh:        make(chan struct{}),
	}

	return ycm, nil
}

// Start init certificate manager and certs for hub agent
func (ycm *yurtHubCertManager) Start() {
	// 1. create ca file for hub certificate manager
	// 1. 初始化本地的CA证书, 实际就是取得apiserver的CA证书存入本地
	err := ycm.initCaCert()
	if err != nil {
		klog.Errorf("failed to init ca cert, %v", err)
		return
	}
	klog.Infof("use %s ca file to bootstrap %s", ycm.caFile, ycm.hubName)

	// 2. create bootstrap config file for hub certificate manager
	// 2. 初始bootstrapConf文件, 包含了token信息, 用于客户端和apiserver进行不需要TLS的通信
	err = ycm.initBootstrap()
	if err != nil {
		klog.Errorf("failed to init bootstrap %v", err)
		return
	}

	// 3. create client certificate manager for hub certificate manager
	// 3. 创建一个Client Certificate Manager, 专门管理k8s客户端的认证信息, 包括发送CSR(认证签名请求)、轮转数字证书等
	// 就是这一步实际生成了公私钥(每次轮转产生一个新的), 并发送了CSR请求(包含yurthub公钥和基本信息), 获得返回的数字证书
	err = ycm.initClientCertificateManager()
	if err != nil {
		klog.Errorf("failed to init client cert manager, %v", err)
		return
	}

	// 4. create hub config file
	// 4. 根据已经生成的认证文件信息(签过名的数字证书), 来生成yurthub与apiserver之间通信的kubeconfig
	err = ycm.initHubConf()
	if err != nil {
		klog.Errorf("failed to init hub config, %v", err)
		return
	}
}

// Stop the cert manager loop
func (ycm *yurtHubCertManager) Stop() {
	if ycm.hubClientCertManager != nil {
		ycm.hubClientCertManager.Stop()
	}
}

// Current returns the currently selected certificate from the certificate manager
func (ycm *yurtHubCertManager) Current() *tls.Certificate {
	if ycm.hubClientCertManager != nil {
		return ycm.hubClientCertManager.Current()
	}

	return nil
}

// ServerHealthy returns true if the cert manager believes the server is currently alive.
func (ycm *yurtHubCertManager) ServerHealthy() bool {
	if ycm.hubClientCertManager != nil {
		return ycm.hubClientCertManager.ServerHealthy()
	}

	return false
}

// Update update bootstrap conf file by new bearer token.
func (ycm *yurtHubCertManager) Update(cfg *config.YurtHubConfiguration) error {
	if cfg == nil {
		return nil
	}

	err := ycm.updateBootstrapConfFile(cfg.JoinToken)
	if err != nil {
		klog.Errorf("could not update hub agent bootstrap config file, %v", err)
		return err
	}

	return nil
}

// GetRestConfig get rest client config from hub agent conf file.
func (ycm *yurtHubCertManager) GetRestConfig() *restclient.Config {
	healthyServer := ycm.remoteServers[0]
	if healthyServer == nil {
		klog.Infof("all of remote servers are unhealthy, so return nil for rest config")
		return nil
	}

	// certificate expired, rest config can not be used to connect remote server,
	// so return nil for rest config
	if ycm.Current() == nil {
		klog.Infof("certificate expired, so return nil for rest config")
		return nil
	}

	hubConfFile := ycm.getHubConfFile()
	if isExist, _ := util.FileExists(hubConfFile); isExist {
		cfg, err := util.LoadRESTClientConfig(hubConfFile)
		if err != nil {
			klog.Errorf("could not get rest config for %s, %v", hubConfFile, err)
			return nil
		}

		// re-fix host connecting healthy server
		cfg.Host = healthyServer.String()
		klog.Infof("re-fix hub rest config host successfully with server %s", cfg.Host)
		return cfg
	}

	klog.Errorf("%s config file(%s) is not exist", ycm.hubName, hubConfFile)
	return nil
}

// GetCaFile returns the path of ca file
func (ycm *yurtHubCertManager) GetCaFile() string {
	return ycm.caFile
}

// NotExpired returns hub client cert is expired or not.
// True: not expired
// False: expired
func (ycm *yurtHubCertManager) NotExpired() bool {
	return ycm.Current() != nil
}

// initCaCert create ca file for hub certificate manager
// 本地没有CA证书时:
// 1. 首先创建一个不需要TLS认证的客户端, 本步骤的通信都是使用这个客户端
// 2. 从apiserver上获取cluster info(获取这个不需要TLS认证)
// 3. 再从cluster info中提取apiserver的CA证书, 写到本地的caFile这个路径下
func (ycm *yurtHubCertManager) initCaCert() error {
	caFile := ycm.getCaFile()
	ycm.caFile = caFile

	if exists, err := util.FileExists(caFile); exists {
		klog.Infof("%s file already exists, so skip to create ca file", caFile)
		return nil
	} else if err != nil {
		klog.Errorf("could not stat ca file %s, %v", caFile, err)
		return err
	} else {
		klog.Infof("%s file not exists, so create it", caFile)
	}

	// 创建一个与apiserver通信的client配置文件, 设置跳过TLS认证
	insecureRestConfig, err := createInsecureRestClientConfig(ycm.remoteServers[0])
	if err != nil {
		klog.Errorf("could not create insecure rest config, %v", err)
		return err
	}

	// 根据上面创建的访问apiserver的client config来创建与apiserver进行通信的client
	insecureClient, err := clientset.NewForConfig(insecureRestConfig)
	if err != nil {
		klog.Errorf("could not new insecure client, %v", err)
		return err
	}

	// make sure configMap kube-public/cluster-info in k8s cluster beforehand
	// 使用上面的客户端与apiserver通信,获取apiserver的cluster info, 获取这个不需要进行TLS认证
	insecureClusterInfo, err := insecureClient.CoreV1().ConfigMaps(metav1.NamespacePublic).Get(context.Background(), ClusterInfoName, metav1.GetOptions{})
	if err != nil {
		klog.Errorf("failed to get cluster-info configmap, %v", err)
		return err
	}

	// 从cluster info中提取kubeconfig数据
	kubeconfigStr, ok := insecureClusterInfo.Data[KubeconfigName]
	if !ok || len(kubeconfigStr) == 0 {
		return fmt.Errorf("no kubeconfig in cluster-info configmap of kube-public namespace")
	}

	kubeConfig, err := clientcmd.Load([]byte(kubeconfigStr))
	if err != nil {
		return fmt.Errorf("could not load kube config string, %v", err)
	}

	if len(kubeConfig.Clusters) != 1 {
		return fmt.Errorf("more than one cluster setting in cluster-info configmap")
	}

	// 从kubeconfig中获取集群的CA信息, 并写到caFile这个路径下
	var clusterCABytes []byte
	for _, cluster := range kubeConfig.Clusters {
		clusterCABytes = cluster.CertificateAuthorityData
	}

	if err := certutil.WriteCert(caFile, clusterCABytes); err != nil {
		klog.Errorf("could not write %s ca cert, %v", ycm.hubName, err)
		return err
	}

	return nil
}

// initBootstrap create bootstrap config file for hub certificate manager
// 初始bootstrapConf文件, 包含了token信息, 用于客户端和apiserver进行不需要TLS的通信, apiserver针对这种通信方式只开放少量的几个权限
func (ycm *yurtHubCertManager) initBootstrap() error {
	bootstrapConfStore, err := disk.NewDiskStorage(ycm.rootDir)
	if err != nil {
		klog.Errorf("could not new disk storage for bootstrap conf file, %v", err)
		return err
	}
	ycm.bootstrapConfStore = bootstrapConfStore

	contents, err := ycm.bootstrapConfStore.Get(BootstrapConfigFileName)
	if err == storage.ErrStorageNotFound {
		klog.Infof("%s bootstrap conf file does not exist, so create it", ycm.hubName)
		return ycm.createBootstrapConfFile(ycm.joinToken)
	} else if err != nil {
		klog.Infof("could not get bootstrap conf file, %v", err)
		return err
	} else if len(contents) == 0 {
		klog.Infof("%s bootstrap conf file does not exist, so create it", ycm.hubName)
		return ycm.createBootstrapConfFile(ycm.joinToken)
	} else {
		klog.Infof("%s bootstrap conf file already exists, skip init bootstrap", ycm.hubName)
		return nil
	}
}

// initClientCertificateManager init hub client certificate manager
// 创建一个Client Certificate Manager, 专门管理k8s客户端的认证信息, 是client-go的库
func (ycm *yurtHubCertManager) initClientCertificateManager() error {
	// 设置存储认证相关文件的位置信息, 此处最后生成的认证信息(包含证书(已经由apiserver签过名的),私钥信息), 存入单个文件为yurthub-current.pem
	// 1. yurthub-current.pem文件中的CERTIFICATE就是数字证书,
	//    每次建立TLS连接, yurthub会把这个证书发送给apiserver, apiserver使用CA机构(实际就是自己的)公钥解码数字证书获得yurthub的公钥
	// 2. yurthub-current.pem文件中的PRIVATE KEY就是: yurthub公钥对应的私钥, 每次与apiserver发送消息会用该私钥加密, 只有用yurthub数字证书中的公钥才可以解码
	//    其中私钥不是我们提供的, 而是开启证书轮转时, 或要进行证书签名请求时, CertificateManager自动生成新的公私钥对
	s, err := certificate.NewFileStore(ycm.hubName, ycm.getPkiDir(), ycm.getPkiDir(), "", "")
	if err != nil {
		klog.Errorf("failed to init %s client cert store, %v", ycm.hubName, err)
		return err

	}
	ycm.hubClientCertPath = s.CurrentPath()

	m, err := certificate.NewManager(&certificate.Config{
		// 用于轮转证书时, 生成与apiserver进行通信的客户端
		ClientFn: ycm.generateCertClientFn,
		// 确定签名者信息,此处设为专门签名kubelet的签名者, 会有kube-controller自动为该请求签名
		SignerName: certificates.KubeAPIServerClientKubeletSignerName,
		// 证书至x509形式的证书
		Template: &x509.CertificateRequest{
			// 表示使用这个数字证书的使用者(组织和用户信息)
			Subject: pkix.Name{
				CommonName:   fmt.Sprintf("system:node:%s", ycm.nodeName),
				Organization: []string{"system:nodes"},
			},
		},
		Usages: []certificates.KeyUsage{
			certificates.UsageDigitalSignature,
			certificates.UsageKeyEncipherment,
			certificates.UsageClientAuth,
		},

		// 设置认证文件保存位置
		CertificateStore: s,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize client certificate manager: %v", err)
	}
	ycm.hubClientCertManager = m
	// 当证书过期后, 用于后台自动轮转证书
	m.Start()

	return nil
}

// getBootstrapClientConfig get rest client config from bootstrap conf file.
// and when no bearer token in bootstrap conf file, kubelet.conf will be used instead.
func (ycm *yurtHubCertManager) getBootstrapClientConfig(healthyServer *url.URL) (*restclient.Config, error) {
	restCfg, err := util.LoadRESTClientConfig(ycm.getBootstrapConfFile())
	if err != nil {
		klog.Errorf("could not load rest client config from bootstrap file(%s), %v", ycm.getBootstrapConfFile(), err)
		return nil, err
	}

	if len(restCfg.BearerToken) != 0 {
		klog.V(3).Infof("join token is set for bootstrap client config")
		// re-fix healthy host for bootstrap client config
		restCfg.Host = healthyServer.String()
		return restCfg, nil
	}

	klog.Infof("no join token, so use kubelet config to bootstrap hub")
	// use kubelet.conf to bootstrap hub agent
	return util.LoadKubeletRestClientConfig(healthyServer)
}

// 用于生成轮转证书时, 与apiserver进行通信的客户端, 此处是: 若本地已经有签名好的证书, 则使用它; 否则使用BootstrapClientConfig
func (ycm *yurtHubCertManager) generateCertClientFn(current *tls.Certificate) (certificatesclient.CertificateSigningRequestInterface, error) {
	var cfg *restclient.Config
	var healthyServer *url.URL
	hubConfFile := ycm.getHubConfFile()

	// 每隔30s轮转一次证书
	_ = wait.PollInfinite(30*time.Second, func() (bool, error) {
		healthyServer = ycm.remoteServers[0]
		if healthyServer == nil {
			klog.V(3).Infof("all of remote servers are unhealthy, just wait")
			return false, nil
		}

		// If we have a valid certificate, use that to fetch CSRs.
		// Otherwise use the bootstrap conf file.
		// 似乎只是检查了是否已经创建过了证书, 并没有进行证书的有效性验证
		if current != nil {
			klog.V(3).Infof("use %s config to create csr client", ycm.hubName)
			// use the valid certificate
			kubeConfig, err := util.LoadRESTClientConfig(hubConfFile)
			if err != nil {
				klog.Errorf("could not load %s kube config, %v", ycm.hubName, err)
				return false, nil
			}

			// re-fix healthy host for cert manager
			kubeConfig.Host = healthyServer.String()
			cfg = kubeConfig
		} else {
			klog.V(3).Infof("use bootstrap client config to create csr client")
			// bootstrap is updated
			bootstrapClientConfig, err := ycm.getBootstrapClientConfig(healthyServer)
			if err != nil {
				klog.Errorf("could not load bootstrap config in clientFn, %v", err)
				return false, nil
			}

			cfg = bootstrapClientConfig
		}

		if cfg != nil {
			klog.V(3).Infof("bootstrap client config: %#+v", cfg)
			// re-fix dial for conn management
			cfg.Dial = ycm.dialer.DialContext
		}
		return true, nil
	})

	// avoid tcp conn leak: certificate rotated, so close old tcp conn that used to rotate certificate
	klog.V(2).Infof("avoid tcp conn leak, close old tcp conn that used to rotate certificate")
	ycm.dialer.Close(strings.Trim(cfg.Host, "https://"))

	client, err := clientset.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return client.CertificatesV1beta1().CertificateSigningRequests(), nil
}

// initHubConf init hub agent conf file.
// 根据已经生成的认证文件信息(签过名的数字证书), 来生成yurthub与apiserver之间通信的kubeconfig
func (ycm *yurtHubCertManager) initHubConf() error {
	hubConfFile := ycm.getHubConfFile()
	if exists, err := util.FileExists(hubConfFile); exists {
		klog.Infof("%s config file already exists, skip init config file", ycm.hubName)
		return nil
	} else if err != nil {
		klog.Errorf("could not stat %s config file %s, %v", ycm.hubName, hubConfFile, err)
		return err
	} else {
		klog.Infof("%s file not exists, so create it", hubConfFile)
	}

	bootstrapClientConfig, err := util.LoadRESTClientConfig(ycm.getBootstrapConfFile())
	if err != nil {
		klog.Errorf("could not load bootstrap client config for init cert store, %v", err)
		return err
	}
	hubClientConfig := restclient.AnonymousClientConfig(bootstrapClientConfig)
	hubClientConfig.KeyFile = ycm.hubClientCertPath
	hubClientConfig.CertFile = ycm.hubClientCertPath
	err = util.CreateKubeConfigFile(hubClientConfig, hubConfFile)
	if err != nil {
		klog.Errorf("could not create %s config file, %v", ycm.hubName, err)
		return err
	}

	return nil
}

// getPkiDir returns the directory for storing hub agent pki
func (ycm *yurtHubCertManager) getPkiDir() string {
	return filepath.Join(ycm.rootDir, HubPkiDirName)
}

// getCaFile returns the path of ca file
func (ycm *yurtHubCertManager) getCaFile() string {
	return filepath.Join(ycm.getPkiDir(), HubCaFileName)
}

// getBootstrapConfFile returns the path of bootstrap conf file
func (ycm *yurtHubCertManager) getBootstrapConfFile() string {
	return filepath.Join(ycm.rootDir, BootstrapConfigFileName)
}

// getHubConfFile returns the path of hub agent conf file.
func (ycm *yurtHubCertManager) getHubConfFile() string {
	return filepath.Join(ycm.rootDir, fmt.Sprintf(HubConfigFileName, ycm.hubName))
}

// createBasic create basic client cmd config
func createBasic(apiServerAddr string, caCert []byte) *clientcmdapi.Config {
	contextName := fmt.Sprintf("%s@%s", BootstrapUser, DefaultClusterName)

	return &clientcmdapi.Config{
		Clusters: map[string]*clientcmdapi.Cluster{
			DefaultClusterName: {
				Server:                   apiServerAddr,
				CertificateAuthorityData: caCert,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			contextName: {
				Cluster:  DefaultClusterName,
				AuthInfo: BootstrapUser,
			},
		},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{},
		CurrentContext: contextName,
	}
}

// createInsecureRestClientConfig create insecure rest client config.
// 创建一个与apiserver通信的client配置文件, 设置跳过TLS认证
func createInsecureRestClientConfig(remoteServer *url.URL) (*restclient.Config, error) {
	if remoteServer == nil {
		return nil, fmt.Errorf("no healthy remote server")
	}
	cfg := createBasic(remoteServer.String(), []byte{})
	cfg.Clusters[DefaultClusterName].InsecureSkipTLSVerify = true

	restConfig, err := clientcmd.NewDefaultClientConfig(*cfg, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create insecure rest client configuration, %v", err)
	}
	return restConfig, nil
}

// createBootstrapConf create bootstrap conf info
func createBootstrapConf(apiServerAddr, caFile, joinToken string) *clientcmdapi.Config {
	if len(apiServerAddr) == 0 || len(caFile) == 0 {
		return nil
	}

	exists, err := util.FileExists(caFile)
	if err != nil || !exists {
		klog.Errorf("ca file(%s) is not exist, %v", caFile, err)
		return nil
	}

	caCert, err := ioutil.ReadFile(caFile)
	if err != nil {
		klog.Errorf("could not read ca file(%s), %v", caFile, err)
		return nil
	}

	cfg := createBasic(apiServerAddr, caCert)
	cfg.AuthInfos[BootstrapUser] = &clientcmdapi.AuthInfo{Token: joinToken}

	return cfg
}

// createBootstrapConfFile create bootstrap conf file
// 根据healthy的apiserver地址、yurthub的CA证书、join token来创建BootstrapConfFile, 并更新到本地磁盘上
func (ycm *yurtHubCertManager) createBootstrapConfFile(joinToken string) error {
	remoteServer := ycm.remoteServers[0]
	if remoteServer == nil || len(remoteServer.Host) == 0 {
		return fmt.Errorf("no healthy server for create bootstrap conf file")
	}

	bootstrapConfig := createBootstrapConf(remoteServer.String(), ycm.caFile, joinToken)
	if bootstrapConfig == nil {
		return fmt.Errorf("could not create bootstrap config for %s", ycm.hubName)
	}

	content, err := clientcmd.Write(*bootstrapConfig)
	if err != nil {
		klog.Errorf("could not create bootstrap config into bytes got error, %v", err)
		return err
	}

	err = ycm.bootstrapConfStore.Update(BootstrapConfigFileName, content)
	if err != nil {
		klog.Errorf("could not create bootstrap conf file(%s), %v", ycm.getBootstrapConfFile(), err)
		return err
	}

	return nil
}

// updateBootstrapConfFile update bearer token in bootstrap conf file
func (ycm *yurtHubCertManager) updateBootstrapConfFile(joinToken string) error {
	if len(joinToken) == 0 {
		return fmt.Errorf("joinToken should not be empty when update bootstrap conf file")
	}

	var curKubeConfig *clientcmdapi.Config
	if existed, _ := util.FileExists(ycm.getBootstrapConfFile()); !existed {
		klog.Infof("bootstrap conf file not exists(maybe deleted unintentionally), so create a new one")
		return ycm.createBootstrapConfFile(joinToken)
	}

	curKubeConfig, err := util.LoadKubeConfig(ycm.getBootstrapConfFile())
	if err != nil || curKubeConfig == nil {
		klog.Errorf("could not get current bootstrap config for %s, %v", ycm.hubName, err)
		return fmt.Errorf("could not load bootstrap conf file(%s), %v", ycm.getBootstrapConfFile(), err)
	}

	if curKubeConfig.AuthInfos[BootstrapUser] != nil {
		if curKubeConfig.AuthInfos[BootstrapUser].Token == joinToken {
			klog.Infof("join token for %s bootstrap conf file is not changed", ycm.hubName)
			return nil
		}
	}

	curKubeConfig.AuthInfos[BootstrapUser] = &clientcmdapi.AuthInfo{Token: joinToken}
	content, err := clientcmd.Write(*curKubeConfig)
	if err != nil {
		klog.Errorf("could not update bootstrap config into bytes, %v", err)
		return err
	}

	err = ycm.bootstrapConfStore.Update(BootstrapConfigFileName, content)
	if err != nil {
		klog.Errorf("could not update bootstrap config, %v", err)
		return err
	}

	return nil
}
