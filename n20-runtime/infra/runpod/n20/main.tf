terraform {
  required_version = ">= 1.11.4"
}

locals {
  profile = jsondecode(file("${path.module}/profile.json"))
}

output "n20_preflight" {
  description = "Provider-free capacity and scenario check; does not acquire GPU resources."
  value = {
    nodes                             = local.profile.nodes
    rounds                            = local.profile.rounds
    gpu_target                        = local.profile.gpu_target
    gpu_count                         = local.profile.gpu_count
    models_per_gpu                    = local.profile.models_per_gpu
    model                             = local.profile.model
    model_revision                    = local.profile.model_revision
    quantization                      = local.profile.quantization
    dtype                             = local.profile.dtype
    thinking                          = local.profile.thinking
    pilot_rounds                      = local.profile.pilot_rounds
    pilot_expected_generations        = [for rounds in local.profile.pilot_rounds : local.profile.nodes * rounds]
    scenario_seed_pairs               = length(local.profile.scenarios) * length(local.profile.seeds)
    generations_per_scenario_and_seed = local.profile.nodes * local.profile.rounds
  }

  precondition {
    condition = (
      local.profile.nodes == 20 &&
      local.profile.rounds == 50 &&
      local.profile.gpu_count == 2 &&
      local.profile.models_per_gpu == 10 &&
      local.profile.nodes == local.profile.gpu_count * local.profile.models_per_gpu &&
      local.profile.inference_layout == "per_node" &&
      local.profile.quantization == "none" &&
      local.profile.dtype == "bfloat16" &&
      jsonencode(local.profile.pilot_rounds) == "[5]" &&
      local.profile.model == "HuggingFaceTB/SmolLM3-3B" &&
      local.profile.model_type == "smollm3" &&
      local.profile.thinking == false &&
      length(local.profile.scenarios) == 17 &&
      jsonencode(local.profile.seeds) == "[0]" &&
      local.profile.pilot.id == "pilot" &&
      local.profile.pilot.malicious_nodes == 0 &&
      local.profile.scenarios[0].id == "C01" &&
      local.profile.scenarios[16].id == "C13"
    )
    error_message = "Expected 20 dedicated unquantized BF16 models on two GPUs, one five-round pilot, and 17 fifty-round scenarios with one shared seed."
  }
}
