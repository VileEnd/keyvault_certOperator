terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # 4.x renamed the federated credential's parent argument from
      # parent_id + resource_group_name to user_assigned_identity_id. The
      # module uses the 4.x form, so an older provider will not plan.
      #
      # 4.42 is the floor because of one attribute: the vault data source's
      # rbac_authorization_enabled, which the permission-model preconditions in
      # main.tf read. It was added in 4.42 and is the only spelling that exists
      # in both 4.x and 5.x -- the older enable_rbac_authorization is gone in
      # 5.x, so a module written against it would not validate there.
      version = ">= 4.42"
    }
  }
}
