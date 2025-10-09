package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func NewGatewayGroupResource() resource.Resource {
	return &gatewayGroupResource{}
}

type gatewayGroupResource struct {
	client *Client
}

func (r *gatewayGroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_gateway_group"
}

func (r *gatewayGroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Patronus gateway group for multi-WAN.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the gateway group.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the gateway group.",
				Optional:    true,
			},
		},
	}
}

func (r *gatewayGroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = req.ProviderData.(*Client)
	}
}

func (r *gatewayGroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {}
func (r *gatewayGroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {}
func (r *gatewayGroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {}
func (r *gatewayGroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {}
