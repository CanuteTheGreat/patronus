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

func NewNatRuleResource() resource.Resource {
	return &natRuleResource{}
}

type natRuleResource struct {
	client *Client
}

type natRuleResourceModel struct {
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	NatType     types.String `tfsdk:"nat_type"`
	Interface   types.String `tfsdk:"interface"`
	SourceAddr  types.String `tfsdk:"source_address"`
	DestAddr    types.String `tfsdk:"dest_address"`
	TransAddr   types.String `tfsdk:"translation_address"`
	TransPort   types.String `tfsdk:"translation_port"`
	Protocol    types.String `tfsdk:"protocol"`
	DestPort    types.String `tfsdk:"dest_port"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func (r *natRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_nat_rule"
}

func (r *natRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Patronus NAT rule.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the NAT rule.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the NAT rule.",
				Optional:    true,
			},
			"nat_type": schema.StringAttribute{
				Description: "NAT type (source, destination, port_forward).",
				Required:    true,
			},
			"interface": schema.StringAttribute{
				Description: "Interface name.",
				Required:    true,
			},
			"source_address": schema.StringAttribute{
				Description: "Source IP address or CIDR.",
				Optional:    true,
			},
			"dest_address": schema.StringAttribute{
				Description: "Destination IP address or CIDR.",
				Optional:    true,
			},
			"translation_address": schema.StringAttribute{
				Description: "Translation (target) IP address.",
				Optional:    true,
			},
			"translation_port": schema.StringAttribute{
				Description: "Translation (target) port.",
				Optional:    true,
			},
			"protocol": schema.StringAttribute{
				Description: "Protocol (tcp, udp, any).",
				Optional:    true,
			},
			"dest_port": schema.StringAttribute{
				Description: "Destination port or port range.",
				Optional:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the rule is enabled.",
				Optional:    true,
			},
		},
	}
}

func (r *natRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *Client, got: %T", req.ProviderData),
		)
		return
	}

	r.client = client
}

func (r *natRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan natRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config := &DeclarativeConfig{
		ApiVersion: "patronus.firewall/v1",
		Kind:       "NatRule",
		Metadata: Metadata{
			Name:        plan.Name.ValueString(),
			Description: plan.Description.ValueString(),
		},
		Spec: map[string]interface{}{
			"nat_type":  plan.NatType.ValueString(),
			"interface": plan.Interface.ValueString(),
			"enabled":   plan.Enabled.ValueBool(),
		},
	}

	if !plan.SourceAddr.IsNull() {
		config.Spec["source_address"] = plan.SourceAddr.ValueString()
	}
	if !plan.DestAddr.IsNull() {
		config.Spec["dest_address"] = plan.DestAddr.ValueString()
	}
	if !plan.TransAddr.IsNull() {
		config.Spec["translation_address"] = plan.TransAddr.ValueString()
	}
	if !plan.TransPort.IsNull() {
		config.Spec["translation_port"] = plan.TransPort.ValueString()
	}
	if !plan.Protocol.IsNull() {
		config.Spec["protocol"] = plan.Protocol.ValueString()
	}
	if !plan.DestPort.IsNull() {
		config.Spec["dest_port"] = plan.DestPort.ValueString()
	}

	err := r.client.ApplyConfig(config)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error creating NAT rule",
			"Could not create NAT rule: "+err.Error(),
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *natRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state natRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config, err := r.client.GetConfig("NatRule", state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading NAT rule",
			"Could not read NAT rule: "+err.Error(),
		)
		return
	}

	if config == nil {
		resp.State.RemoveResource(ctx)
		return
	}

	if desc, ok := config.Metadata.Description; ok && desc != "" {
		state.Description = types.StringValue(desc)
	}

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *natRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan natRuleResourceModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	config := &DeclarativeConfig{
		ApiVersion: "patronus.firewall/v1",
		Kind:       "NatRule",
		Metadata: Metadata{
			Name:        plan.Name.ValueString(),
			Description: plan.Description.ValueString(),
		},
		Spec: map[string]interface{}{
			"nat_type":  plan.NatType.ValueString(),
			"interface": plan.Interface.ValueString(),
			"enabled":   plan.Enabled.ValueBool(),
		},
	}

	if !plan.SourceAddr.IsNull() {
		config.Spec["source_address"] = plan.SourceAddr.ValueString()
	}
	if !plan.DestAddr.IsNull() {
		config.Spec["dest_address"] = plan.DestAddr.ValueString()
	}
	if !plan.TransAddr.IsNull() {
		config.Spec["translation_address"] = plan.TransAddr.ValueString()
	}
	if !plan.TransPort.IsNull() {
		config.Spec["translation_port"] = plan.TransPort.ValueString()
	}
	if !plan.Protocol.IsNull() {
		config.Spec["protocol"] = plan.Protocol.ValueString()
	}
	if !plan.DestPort.IsNull() {
		config.Spec["dest_port"] = plan.DestPort.ValueString()
	}

	err := r.client.ApplyConfig(config)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error updating NAT rule",
			"Could not update NAT rule: "+err.Error(),
		)
		return
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *natRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state natRuleResourceModel
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.RemoveConfig("NatRule", state.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			"Error deleting NAT rule",
			"Could not delete NAT rule: "+err.Error(),
		)
		return
	}
}
