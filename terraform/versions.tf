terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # 4.x renamed the federated credential's parent argument from
      # parent_id + resource_group_name to user_assigned_identity_id. The
      # module uses the 4.x form, so an older provider will not plan.
      version = ">= 4.0"
    }
  }
}
