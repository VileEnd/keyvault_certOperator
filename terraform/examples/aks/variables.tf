variable "resource_group_name" {
  description = "Resource group holding the AKS cluster."
  type        = string
}

variable "location" {
  description = "Azure region."
  type        = string
}

variable "cluster_name" {
  description = "Name of the existing AKS cluster."
  type        = string
}

variable "key_vault_name" {
  description = "Name of the existing Key Vault the certificates are written to."
  type        = string
}

variable "key_vault_resource_group_name" {
  description = "Resource group holding the Key Vault. Often not the cluster's."
  type        = string
}

variable "application_gateway_principal_id" {
  description = "Principal ID of the gateway's identity, to grant Key Vault Secrets User. Null to skip."
  type        = string
  default     = null
}

variable "chart_repository" {
  description = "Helm repository hosting the chart. Use null with a local path in chart_name."
  type        = string
  default     = null
}

variable "chart_name" {
  description = "Chart name, or a local path such as ../../../charts/keyvault-certoperator."
  type        = string
  default     = "../../../charts/keyvault-certoperator"
}

variable "chart_version" {
  description = "Chart version. Null tracks whatever the repository serves, which is not what you want in production."
  type        = string
  default     = null
}
