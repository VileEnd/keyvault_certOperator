terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
      # The federated credential sets the floor. azurerm_federated_identity_credential
      # took parent_id + resource_group_name up to and including 4.64;
      # user_assigned_identity_id, the form main.tf uses, arrives in 4.65.0. On
      # anything older the module does not even validate -- it fails with
      # "The argument parent_id is required" -- so 4.x on its own is not the
      # constraint, 4.65 is.
      #
      # The vault data source's rbac_authorization_enabled, which the
      # permission-model preconditions in main.tf read, is the secondary and
      # subsumed constraint: added in 4.42. It is worth naming because it is the
      # only spelling that exists in both 4.x and 5.x -- the older
      # enable_rbac_authorization is gone in 5.x, so a module written against
      # that one would not validate there.
      version = ">= 4.65"
    }
  }
}
