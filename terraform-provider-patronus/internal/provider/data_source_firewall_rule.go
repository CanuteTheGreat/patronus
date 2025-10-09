package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func NewFirewallRuleDataSource() datasource.DataSource {
	return &firewallRuleDataSource{}
}

type firewallRuleDataSource struct {
	client *Client
}

type firewallRuleDataSourceModel struct {
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Action      types.String `tfsdk:"action"`
	Interface   types.String `tfsdk:"interface"`
}

func (d *firewallRuleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule"
}

func (d *firewallRuleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fetches a Patronus firewall rule.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the firewall rule.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the firewall rule.",
				Computed:    true,
			},
			"action": schema.StringAttribute{
				Description: "Action (allow, deny, reject).",
				Computed:    true,
			},
			"interface": schema.StringAttribute{
				Description: "Interface name.",
				Computed:    true,
			},
		},
	}
}

func (d *firewallRuleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData != nil {
		d.client = req.ProviderData.(*Client)
	}
}

func (d *firewallRuleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data firewallRuleDataSourceModel

	diags := req.Config.Get(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get config from client
	config, err := d.client.GetConfig("FirewallRule", data.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading firewall rule",
			"Could not read firewall rule: "+err.Error(),
		)
		return
	}

	if config != nil {
		data.Description = types.StringValue(config.Metadata.Description)
		if action, ok := config.Spec["action"].(string); ok {
			data.Action = types.StringValue(action)
		}
		if iface, ok := config.Spec["interface"].(string); ok {
			data.Interface = types.StringValue(iface)
		}
	}

	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
}
