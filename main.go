package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"

	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
)

var GroupName = os.Getenv("GROUP_NAME")

// 禁用CHAME记录，不然影响DNS01查询结果
var DisableCHAME = []string{
	"@",
	"*",
}

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&dnsPodProviderSolver{},
	)
}

// dnsPodProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type dnsPodProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client       *kubernetes.Clientset
	dnspodClient *dnspod.Client
}

// dnspodReq dnspod请求所需
type dnspodReq struct {
	Domain    string //域名
	Subdomain string //子域名
	//RecordId  string //记录ID
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type dnsPodDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	SecretId     cmmetav1.SecretKeySelector `json:"secretIdSecretRef"`
	SecretKey    cmmetav1.SecretKeySelector `json:"secretKeySecretRef"`
	DisableCHAME cmmetav1.SecretKeySelector `json:"disableCHAME"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *dnsPodProviderSolver) Name() string {
	return "dnspod-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *dnsPodProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	//ctx := context.Background()
	klog.InfoS("Presenting challenge", "dnsName", ch.DNSName, "resolvedZone", ch.ResolvedZone, "resolvedFQDN", ch.ResolvedFQDN)
	podclient, err := c.initpoddnsclient(ch)
	if err != nil {
		return err
	}
	c.dnspodClient = podclient
	podMode := convertDnsPod(ch.ResolvedZone, ch.ResolvedFQDN)
	klog.Infof("[%s]转换后的域名:[%s]子域名[%s]", ch.ResolvedFQDN, podMode.Domain, podMode.Subdomain)
	_, zoneName, err := c.getHostedZone(podMode.Domain)
	if err != nil {
		return fmt.Errorf("failed to get dnspod hosted zone: %v error:%v", zoneName, err)
	}
	recordAttributes := c.newTxtRecord(podMode.Domain, podMode.Subdomain, ch.Key)
	_, err = c.dnspodClient.CreateRecord(recordAttributes)
	if err != nil {
		return fmt.Errorf("failed to get dnspod domain record: %v", err)
	}
	c.modifiedChameStatu(*zoneName, false) //需要禁用CHAME状态不然查询TXT会失败
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *dnsPodProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.InfoS("Presenting challenge", "dnsName", ch.DNSName, "resolvedZone", ch.ResolvedZone, "resolvedFQDN", ch.ResolvedFQDN)
	podMode := convertDnsPod(ch.ResolvedZone, ch.ResolvedFQDN)
	klog.Infof("[%s]转换后的域名:[%s]子域名[%s]", ch.ResolvedFQDN, podMode.Domain, podMode.Subdomain)
	_, zoneName, err := c.getHostedZone(podMode.Domain)
	if err != nil {
		return fmt.Errorf("failed to get dnspod hosted zone: %v error:%v", zoneName, err)
	}
	records, err := c.findTxtRecords(podMode.Domain, podMode.Subdomain, "TXT")
	if err != nil {
		return fmt.Errorf("failed to get dnspod finding txt record: %v", err)
	}
	if records == nil || records.Response == nil || len(records.Response.RecordList) <= 0 {
		return nil
	}
	for _, record := range records.Response.RecordList {
		request := dnspod.NewDeleteRecordRequest()
		request.Domain = common.StringPtr(util.UnFqdn(ch.ResolvedZone))
		request.RecordId = record.RecordId
		_, err := c.dnspodClient.DeleteRecord(request)
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			klog.InfoS("An API error has returned: %s", err)
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to get dnspod delete txt record: %v", err)
		}
	}
	c.modifiedChameStatu(*zoneName, true) //需要禁用CHAME状态不然查询TXT会失败
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *dnsPodProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (dnsPodDNSProviderConfig, error) {
	cfg := dnsPodDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

// loadSecretData Load Secret key data
func (c *dnsPodProviderSolver) loadSecretData(selector cmmetav1.SecretKeySelector, ns string) ([]byte, error) {
	secret, err := c.client.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to load secret %q errors:%v", ns+"/"+selector.Name, err)
	}

	if data, ok := secret.Data[selector.Key]; ok {
		return data, nil
	}

	return nil, fmt.Errorf("no key %q in secret %q", selector.Key, ns+"/"+selector.Name)
}

// initpoddnsclient Initialize the client
func (c *dnsPodProviderSolver) initpoddnsclient(ch *v1alpha1.ChallengeRequest) (*dnspod.Client, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.Errorf("Load configuration error:%s", err)
		return nil, err
	}
	klog.Infof("密匙名称:%s", cfg.SecretId.Name)
	secretID, err := c.loadSecretData(cfg.SecretId, ch.ResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get domain id %s: %v", ch.ResolvedZone, err)
	}
	secretKey, err := c.loadSecretData(cfg.SecretKey, ch.ResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get key id %s: %v", ch.ResolvedZone, err)
	}
	credential := common.NewCredential(string(secretID), string(secretKey))
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "dnspod.tencentcloudapi.com"

	client, err := dnspod.NewClient(credential, "", cpf)
	if err != nil {
		return nil, fmt.Errorf("failed to get dnspod client %v: %v", cfg, err)
	}
	return client, nil
}

// getHostedZone Get a list of domain names
func (c *dnsPodProviderSolver) getHostedZone(resolvedZone string) (*uint64, *string, error) {
	request := dnspod.NewDescribeDomainListRequest()
	response, err := c.dnspodClient.DescribeDomainList(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		klog.Error("An API error has returned: %s", err)
		return nil, nil, err
	}

	if response.Response == nil || len(response.Response.DomainList) <= 0 {
		return nil, nil, fmt.Errorf("no list of domain names found")
	}

	domains := response.Response.DomainList
	var hostedZone *dnspod.DomainListItem
	for _, zone := range domains {
		if zone.Name != nil && *zone.Name == util.UnFqdn(resolvedZone) {
			hostedZone = zone
		}
	}

	if hostedZone == nil || hostedZone.DomainId == nil {
		return nil, nil, fmt.Errorf("zone %s not found in dnsPod", resolvedZone)
	}
	return hostedZone.DomainId, hostedZone.Name, nil
}

// findTxtRecords Find the specified TXT record
func (c *dnsPodProviderSolver) findTxtRecords(zone, fqdn, recordType string) (*dnspod.DescribeRecordListResponse, error) {
	request := dnspod.NewDescribeRecordListRequest()
	request.Subdomain = common.StringPtr(fqdn)
	request.Domain = common.StringPtr(zone)
	request.RecordType = common.StringPtr(recordType)
	response, err := c.dnspodClient.DescribeRecordList(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		klog.Infof("域名[%s]未查找到[%s]指定记录！", zone, fqdn)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return response, nil
}

// newTxtRecord
func (c *dnsPodProviderSolver) newTxtRecord(zone, fqdn, value string) *dnspod.CreateRecordRequest {
	request := dnspod.NewCreateRecordRequest()
	request.SubDomain = common.StringPtr(fqdn)
	request.Domain = common.StringPtr(zone)
	request.RecordType = common.StringPtr("TXT")
	request.RecordLine = common.StringPtr("默认")
	request.Value = common.StringPtr(value)
	return request
}

func (c *dnsPodProviderSolver) modifiedChameStatu(zone string, state bool) error {
	for _, name := range DisableCHAME {
		records, err := c.findTxtRecords(zone, name, "CHAME")
		if err != nil {
			return err
		}
		if records == nil || records.Response == nil || len(records.Response.RecordList) <= 0 {
			return nil
		}
		for _, record := range records.Response.RecordList {
			klog.Info("正在修改域名[%s]中的CHAME状态防止查找不到[%s][%v]", zone, name, state)
			modify := dnspod.NewModifyRecordRequest()
			modify.Domain = &zone
			modify.RecordId = record.RecordId
			if state {
				modify.Status = common.StringPtr("ENABLE")
			} else {
				modify.Status = common.StringPtr("DISABLE")
			}
			_, err = c.dnspodClient.ModifyRecord(modify)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// convertDnsPod convert
func convertDnsPod(zone, fqdn string) dnspodReq {
	request := dnspodReq{}
	request.Subdomain = util.UnFqdn(fqdn[:len(fqdn)-len(zone)])
	request.Domain = util.UnFqdn(zone)
	return request
}
