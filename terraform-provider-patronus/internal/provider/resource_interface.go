package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func NewInterfaceResource() resource.Resource {
	return &interfaceResource{}
}

type interfaceResource struct {
	client *Client
}

func (r *interfaceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_interface"
}

func (r *interfaceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a Patronus network interface.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the interface.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "Description of the interface.",
				Optional:    true,
			},
			"enabled": schema.BoolAttribute{
				Description: "Whether the interface is enabled.",
				Optional:    true,
			},
		},
	}
}

func (r *interfaceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.client = req.ProviderData.(*Client)
	}
}

func (r *interfaceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {}
func (r *interfaceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {}
func (r *interfaceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {}
func (r *interfaceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {}
