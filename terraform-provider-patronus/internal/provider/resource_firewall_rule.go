package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource              = &firewallRuleResource{}
	_ resource.ResourceWithConfigure = &firewallRuleResource{}
)

// NewFirewallRuleResource is a helper function to simplify the provider implementation.
func NewFirewallRuleResource() resource.Resource {
	return &firewallRuleResource{}
}

// firewallRuleResource is the resource implementation.
type firewallRuleResource struct {
	client *Client
}

// firewallRuleResourceModel maps the resource schema data.
type firewallRuleResourceModel struct {
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	Action      types.String `tfsdk:"action"`
	Interface   types.String `tfsdk:"interface"`
	Direction   types.String `tfsdk:"direction"`
	Protocol    types.String `tfsdk:"protocol"`
	SourceAddr  types.String `tfsdk:"source_address"`
	SourcePort  types.String `tfsdk:"source_port"`
	DestAddr    types.String `tfsdk:"dest_address"`
	DestPort    types.String `tfsdk:"dest_port"`
	Log         types.Bool   `tfsdk:"log"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

// Metadata returns the resource type name.
func (r *firewallRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_firewall_rule"
}

// Schema defines the schema for the resource.
func (r *firewallRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Patronus firewall rule.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the firewall rule.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the firewall rule.",
				Optional:    true,
			},
			"action": schema.StringAttribute{
				Description: "Action to take (allow, deny, reject).",
				Required:    true,
			},
			"interface": schema.StringAttribute{
				Description: "Interface name (e.g., wan0, lan0).",
				Optional:    true,
			},
			"direction": schema.StringAttribute{
				Description: "Direction (inbound, outbound).",
				Optional:    true,
			},
			"protocol": schema.StringAttribute{
				Description: "Protocol (tcp, udp, icmp, any).",
				Optional:    true,
			},
			"source_address": schema.StringAttribute{
				Description: "Source IP address or CIDR.",
				Optional:    true,
			},
			"source_port": schema.StringAttribute{
				Description: "Source port or port range.",
				Optional:    true,
			},
			"dest_address": schema.StringAttribute{
				Description: "Destination IP address or CIDR.",
				Optional:    true,
			},
			"dest_port": schema.StringAttribute{
				Description: "Destination port or port range.",
				Optional:    true,
			},
			"log": schema.BoolAttribute{
				Description: "Enable logging for this rule.",
				Optional:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the rule is enabled.",
				Optional:    true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *firewallRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = client
}

// Create creates the resource and sets the initial Terraform state.
func (r *firewallRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan firewallRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build declarative config
	config := &DeclarativeConfig{
		ApiVersion: "patronus.firewall/v1",
		Kind:       "FirewallRule",
		Metadata: Metadata{
			Name:        plan.Name.ValueString(),
			Description: plan.Description.ValueString(),
		},
		Spec: map[string]interface{}{
			"action":   plan.Action.ValueString(),
			"log":      plan.Log.ValueBool(),
			"enabled":  plan.Enabled.ValueBool(),
		},
	}

	// Add optional fields
	if !plan.Interface.IsNull() {
		config.Spec["interface"] = plan.Interface.ValueString()
	}
	if !plan.Direction.IsNull() {
		config.Spec["direction"] = plan.Direction.ValueString()
	}
	if !plan.Protocol.IsNull() {
		config.Spec["protocol"] = plan.Protocol.ValueString()
	}

	// Source specification
	source := make(map[string]interface{})
	if !plan.SourceAddr.IsNull() {
		source["address"] = plan.SourceAddr.ValueString()
	}
	if !plan.SourcePort.IsNull() {
		source["ports"] = plan.SourcePort.ValueString()
	}
	if len(source) > 0 {
		config.Spec["source"] = source
	}

	// Destination specification
	dest := make(map[string]interface{})
	if !plan.DestAddr.IsNull() {
		dest["address"] = plan.DestAddr.ValueString()
	}
	if !plan.DestPort.IsNull() {
		dest["ports"] = plan.DestPort.ValueString()
	}
	if len(dest) > 0 {
		config.Spec["destination"] = dest
	}

	// Apply config
	err := r.client.ApplyConfig(config)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating firewall rule",
			"Could not create firewall rule: "+err.Error(),
		)
		return
	}

	// Set state
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Read refreshes the Terraform state with the latest data.
func (r *firewallRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state firewallRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get config from client
	config, err := r.client.GetConfig("FirewallRule", state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading firewall rule",
			"Could not read firewall rule: "+err.Error(),
		)
		return
	}

	if config == nil {
		// Rule no longer exists
		resp.State.RemoveResource(ctx)
		return
	}

	// Update state from config
	if desc, ok := config.Metadata.Description; ok && desc != "" {
		state.Description = types.StringValue(desc)
	}

	if action, ok := config.Spec["action"].(string); ok {
		state.Action = types.StringValue(action)
	}

	// Set state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *firewallRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan firewallRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build updated config (same as Create)
	config := &DeclarativeConfig{
		ApiVersion: "patronus.firewall/v1",
		Kind:       "FirewallRule",
		Metadata: Metadata{
			Name:        plan.Name.ValueString(),
			Description: plan.Description.ValueString(),
		},
		Spec: map[string]interface{}{
			"action":   plan.Action.ValueString(),
			"log":      plan.Log.ValueBool(),
			"enabled":  plan.Enabled.ValueBool(),
		},
	}

	// Add optional fields
	if !plan.Interface.IsNull() {
		config.Spec["interface"] = plan.Interface.ValueString()
	}
	if !plan.Direction.IsNull() {
		config.Spec["direction"] = plan.Direction.ValueString()
	}
	if !plan.Protocol.IsNull() {
		config.Spec["protocol"] = plan.Protocol.ValueString()
	}

	// Source specification
	source := make(map[string]interface{})
	if !plan.SourceAddr.IsNull() {
		source["address"] = plan.SourceAddr.ValueString()
	}
	if !plan.SourcePort.IsNull() {
		source["ports"] = plan.SourcePort.ValueString()
	}
	if len(source) > 0 {
		config.Spec["source"] = source
	}

	// Destination specification
	dest := make(map[string]interface{})
	if !plan.DestAddr.IsNull() {
		dest["address"] = plan.DestAddr.ValueString()
	}
	if !plan.DestPort.IsNull() {
		dest["ports"] = plan.DestPort.ValueString()
	}
	if len(dest) > 0 {
		config.Spec["destination"] = dest
	}

	// Apply config
	err := r.client.ApplyConfig(config)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating firewall rule",
			"Could not update firewall rule: "+err.Error(),
		)
		return
	}

	// Set state
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *firewallRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state firewallRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete via client
	err := r.client.RemoveConfig("FirewallRule", state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting firewall rule",
			"Could not delete firewall rule: "+err.Error(),
		)
		return
	}
}
