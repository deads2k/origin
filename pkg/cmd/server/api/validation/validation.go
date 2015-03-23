package validation

import (
	"fmt"
	"net"
	"os"
	"strings"

	errs "github.com/GoogleCloudPlatform/kubernetes/pkg/api/errors"
	kvalidation "github.com/GoogleCloudPlatform/kubernetes/pkg/api/validation"

	"github.com/openshift/origin/pkg/cmd/server/api"
)

func ValidateBindAddress(bindAddress string) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(bindAddress) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("bindAddress"))
	} else if _, _, err := net.SplitHostPort(bindAddress); err != nil {
		allErrs = append(allErrs, errs.NewFieldInvalid("bindAddress", bindAddress, "must be a host:port"))
	}

	return allErrs
}

func ValidateServingInfo(info api.ServingInfo) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	allErrs = append(allErrs, ValidateBindAddress(info.BindAddress)...)
	allErrs = append(allErrs, ValidateCertInfo(info.ServerCert)...)

	if len(info.ClientCA) > 0 {
		if (len(info.ServerCert.CertFile) == 0) || (len(info.ServerCert.KeyFile) == 0) {
			allErrs = append(allErrs, errs.NewFieldInvalid("clientCA", info.ClientCA, "cannot specify a clientCA without a certFile"))
		}

		allErrs = append(allErrs, ValidateFile(info.ClientCA, "clientCA")...)
	}

	return allErrs
}

func ValidateKubeConfig(path string, field string) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	allErrs = append(allErrs, ValidateFile(path, field)...)
	// TODO: load and parse

	return allErrs
}

func ValidateKubernetesMasterConfig(config *api.KubernetesMasterConfig) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(config.MasterIP) > 0 {
		allErrs = append(allErrs, ValidateSpecifiedIP(config.MasterIP, "masterIP")...)
	}

	if len(config.ServicesSubnet) > 0 {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(config.ServicesSubnet)); err != nil {
			allErrs = append(allErrs, errs.NewFieldInvalid("servicesSubnet", config.ServicesSubnet, "must be a valid CIDR notation IP range (e.g. 172.30.17.0/24)"))
		}
	}

	if len(config.SchedulerConfigFile) > 0 {
		allErrs = append(allErrs, ValidateFile(config.SchedulerConfigFile, "schedulerConfigFile")...)
	}

	return allErrs
}

func ValidateOAuthConfig(config *api.OAuthConfig) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(config.ProxyCA) > 0 {
		allErrs = append(allErrs, ValidateFile(config.ProxyCA, "proxyCA")...)
	}

	if len(config.MasterURL) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("masterURL"))
	}

	if len(config.MasterPublicURL) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("masterPublicURL"))
	}

	if len(config.AssetPublicURL) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("assetPublicURL"))
	}

	if config.SessionAuthenticationConfig != nil {
		allErrs = append(allErrs, ValidateSessionAuthenticationConfig(config.SessionAuthenticationConfig).Prefix("sessionAuthenticationConfig")...)
	}

	allErrs = append(allErrs, ValidateGrantConfig(config.GrantConfig).Prefix("grantConfig")...)

	for i, identityProvider := range config.IdentityProviders {
		allErrs = append(allErrs, ValidateIdentityProvider(identityProvider).Prefix(fmt.Sprintf("identityProvider[%d]", i))...)
	}

	return allErrs
}

func ValidateIdentityProvider(identityProvider api.IdentityProvider) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(identityProvider.Usage.ProviderScope) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("usage.providerScope"))
	}

	if !api.IsIdentityProviderType(identityProvider.Provider) {
		allErrs = append(allErrs, errs.NewFieldInvalid("provider", identityProvider.Provider, fmt.Sprintf("%v is invalid in this context", identityProvider.Provider)))
	} else {
		switch provider := identityProvider.Provider.Object.(type) {
		case (*api.XRemoteUserIdentityProvider):
			if len(provider.CAFile) > 0 {
				allErrs = append(allErrs, ValidateFile(provider.CAFile, "provider.caFile")...)
			}
			if len(provider.Headers) == 0 {
				allErrs = append(allErrs, errs.NewFieldRequired("provider.headers"))
			}

		case (*api.BasicAuthPasswordIdentityProvider):
			allErrs = append(allErrs, ValidateRemoteConnectionInfo(provider.RemoteConnectionInfo).Prefix("provider")...)

		case (*api.HTPasswdPasswordIdentityProvider):
			allErrs = append(allErrs, ValidateFile(provider.File, "provider.file")...)

		case (*api.OAuthRedirectingIdentityProvider):
			if len(provider.ClientID) == 0 {
				allErrs = append(allErrs, errs.NewFieldRequired("provider.clientID"))
			}
			if len(provider.ClientSecret) == 0 {
				allErrs = append(allErrs, errs.NewFieldRequired("provider.clientSecret"))
			}
			if !api.IsOAuthProviderType(provider.Provider) {
				allErrs = append(allErrs, errs.NewFieldInvalid("provider.provider", provider.Provider, fmt.Sprintf("%v is invalid in this context", identityProvider.Provider)))
			}
		}

	}

	return allErrs
}

func ValidateRemoteConnectionInfo(remoteConnectionInfo api.RemoteConnectionInfo) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(remoteConnectionInfo.URL) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("url"))
	}

	if len(remoteConnectionInfo.CA) > 0 {
		allErrs = append(allErrs, ValidateFile(remoteConnectionInfo.CA, "ca")...)
	}

	allErrs = append(allErrs, ValidateCertInfo(remoteConnectionInfo.ClientCert)...)

	return allErrs
}

func ValidateCertInfo(certInfo api.CertInfo) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(certInfo.CertFile) > 0 {
		if len(certInfo.KeyFile) == 0 {
			allErrs = append(allErrs, errs.NewFieldRequired("keyFile"))
		}

		allErrs = append(allErrs, ValidateFile(certInfo.CertFile, "certFile")...)
	}

	if len(certInfo.KeyFile) > 0 {
		if len(certInfo.CertFile) == 0 {
			allErrs = append(allErrs, errs.NewFieldRequired("certFile"))
		}

		allErrs = append(allErrs, ValidateFile(certInfo.KeyFile, "keyFile")...)
	}

	return allErrs
}

func ValidateGrantConfig(config api.GrantConfig) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if !api.ValidGrantHandlerTypes.Has(string(config.Method)) {
		allErrs = append(allErrs, errs.NewFieldInvalid("grantConfig.method", config.Method, fmt.Sprintf("must be one of: %v", api.ValidGrantHandlerTypes.List())))
	}

	return allErrs
}

func ValidateSessionAuthenticationConfig(config *api.SessionAuthenticationConfig) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(config.SessionSecrets) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("sessionSecrets"))
	}
	if len(config.SessionName) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("sessionName"))
	}

	return allErrs
}

func ValidateSpecifiedIP(ipString string, field string) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	ip := net.ParseIP(ipString)
	if ip == nil {
		allErrs = append(allErrs, errs.NewFieldInvalid(field, ipString, "must be a valid IP"))
	} else if ip.IsUnspecified() {
		allErrs = append(allErrs, errs.NewFieldInvalid(field, ipString, "cannot be an unspecified IP"))
	}

	return allErrs
}

func ValidateMasterConfig(config *api.MasterConfig) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	allErrs = append(allErrs, ValidateServingInfo(config.ServingInfo).Prefix("servingInfo")...)

	if config.AssetConfig != nil {
		allErrs = append(allErrs, ValidateServingInfo(config.AssetConfig.ServingInfo).Prefix("assetConfig.servingInfo")...)
	}

	if config.DNSConfig != nil {
		allErrs = append(allErrs, ValidateBindAddress(config.DNSConfig.BindAddress).Prefix("dnsConfig")...)
	}

	if config.KubernetesMasterConfig != nil {
		allErrs = append(allErrs, ValidateKubernetesMasterConfig(config.KubernetesMasterConfig).Prefix("kubernetesMasterConfig")...)
	}

	allErrs = append(allErrs, ValidatePolicyConfig(config.PolicyConfig).Prefix("policyConfig")...)
	allErrs = append(allErrs, ValidateOAuthConfig(config.OAuthConfig).Prefix("oauthConfig")...)

	allErrs = append(allErrs, ValidateKubeConfig(config.MasterClients.DeployerKubeConfig, "deployerKubeConfig").Prefix("masterClients")...)
	allErrs = append(allErrs, ValidateKubeConfig(config.MasterClients.OpenShiftLoopbackKubeConfig, "openShiftLoopbackKubeConfig").Prefix("masterClients")...)
	allErrs = append(allErrs, ValidateKubeConfig(config.MasterClients.KubernetesKubeConfig, "kubernetesKubeConfig").Prefix("masterClients")...)

	return allErrs
}

func ValidatePolicyConfig(config api.PolicyConfig) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	allErrs = append(allErrs, ValidateFile(config.BootstrapPolicyFile, "bootstrapPolicyFile")...)
	allErrs = append(allErrs, ValidateNamespace(config.MasterAuthorizationNamespace, "masterAuthorizationNamespace")...)
	allErrs = append(allErrs, ValidateNamespace(config.OpenShiftSharedResourcesNamespace, "openShiftSharedResourcesNamespace")...)

	return allErrs
}

func ValidateNamespace(namespace, field string) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(namespace) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired(field))
	} else if ok, _ := kvalidation.ValidateNamespaceName(namespace, false); !ok {
		allErrs = append(allErrs, errs.NewFieldInvalid(field, namespace, "must be a valid namespace"))
	}

	return allErrs
}

func ValidateNodeConfig(config *api.NodeConfig) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(config.NodeName) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("nodeName"))
	}

	allErrs = append(allErrs, ValidateServingInfo(config.ServingInfo).Prefix("servingInfo")...)
	allErrs = append(allErrs, ValidateKubeConfig(config.MasterKubeConfig, "masterKubeConfig")...)

	if len(config.DNSIP) > 0 {
		allErrs = append(allErrs, ValidateSpecifiedIP(config.DNSIP, "dnsIP")...)
	}

	if len(config.NetworkContainerImage) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired("networkContainerImage"))
	}

	return allErrs
}

func ValidateFile(path string, field string) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	if len(path) == 0 {
		allErrs = append(allErrs, errs.NewFieldRequired(field))
	} else if _, err := os.Stat(path); err != nil {
		allErrs = append(allErrs, errs.NewFieldInvalid(field, path, "could not read file"))
	}

	return allErrs
}

func ValidateAllInOneConfig(master *api.MasterConfig, node *api.NodeConfig) errs.ValidationErrorList {
	allErrs := errs.ValidationErrorList{}

	allErrs = append(allErrs, ValidateMasterConfig(master).Prefix("masterConfig")...)

	allErrs = append(allErrs, ValidateNodeConfig(node).Prefix("nodeConfig")...)

	// Validation between the configs

	return allErrs
}
