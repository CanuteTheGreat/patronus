package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ provider.Provider = &patronusProvider{}
)

// New is a helper function to simplify provider server and testing implementation.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &patronusProvider{
			version: version,
		}
	}
}

// patronusProvider is the provider implementation.
type patronusProvider struct {
	version string
}

// patronusProviderModel maps provider schema data to a Go type.
type patronusProviderModel struct {
	ConfigPath types.String `tfsdk:"config_path"`
	ApiUrl     types.String `tfsdk:"api_url"`
	ApiToken   types.String `tfsdk:"api_token"`
}

// Metadata returns the provider type name.
func (p *patronusProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "patronus"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *patronusProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Interact with Patronus Firewall via declarative configuration.",
		Attributes: map[string]schema.Attribute{
			"config_path": schema.StringAttribute{
				Description: "Path to Patronus configuration directory. May also be provided via PATRONUS_CONFIG_PATH environment variable.",
				Optional:    true,
			},
			"api_url": schema.StringAttribute{
				Description: "Patronus API URL. May also be provided via PATRONUS_API_URL environment variable.",
				Optional:    true,
			},
			"api_token": schema.StringAttribute{
				Description: "Patronus API authentication token. May also be provided via PATRONUS_API_TOKEN environment variable.",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

// Configure prepares a Patronus API client for data sources and resources.
func (p *patronusProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config patronusProviderModel
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Configuration values are now available.
	// If config_path is unknown or null, default to environment variable
	configPath := os.Getenv("PATRONUS_CONFIG_PATH")
	if !config.ConfigPath.IsNull() {
		configPath = config.ConfigPath.ValueString()
	}

	apiUrl := os.Getenv("PATRONUS_API_URL")
	if !config.ApiUrl.IsNull() {
		apiUrl = config.ApiUrl.ValueString()
	}

	apiToken := os.Getenv("PATRONUS_API_TOKEN")
	if !config.ApiToken.IsNull() {
		apiToken = config.ApiToken.ValueString()
	}

	// Default config path
	if configPath == "" {
		configPath = "/etc/patronus/config"
	}

	// Create client
	client := &Client{
		ConfigPath: configPath,
		ApiUrl:     apiUrl,
		ApiToken:   apiToken,
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

// DataSources defines the data sources implemented in the provider.
func (p *patronusProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewFirewallRuleDataSource,
	}
}

// Resources defines the resources implemented in the provider.
func (p *patronusProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewFirewallRuleResource,
		NewNatRuleResource,
		NewInterfaceResource,
		NewGatewayGroupResource,
	}
}
