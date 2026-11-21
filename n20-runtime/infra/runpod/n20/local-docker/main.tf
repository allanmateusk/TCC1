terraform {
  required_version = "= 1.11.4"

  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "= 3.6.2"
    }
  }
}

# Fixed Windows named pipe: never read DOCKER_HOST or the active Docker context.
provider "docker" {
  host = "npipe:////./pipe/dockerDesktopLinuxEngine"
}

variable "run_id" {
  type = string
  validation {
    condition     = can(regex("^[a-f0-9]{12}$", var.run_id))
    error_message = "Use a fresh run ID with 12 lowercase hexadecimal characters."
  }
}

variable "archive" {
  type        = string
  description = "Absolute host path to the small, locally generated code/data ZIP."
  validation {
    condition     = fileexists(var.archive) && endswith(var.archive, ".zip")
    error_message = "Generate the dedicated ZIP before planning."
  }
}

variable "python_image" {
  type        = string
  description = "Digest of an official Docker Hub Python image already resolved locally."
  validation {
    condition     = can(regex("^docker\\.io/library/python@sha256:[0-9a-f]{64}$", var.python_image))
    error_message = "Only an immutable Docker Official Image for Python is permitted."
  }
}

resource "docker_image" "python" {
  name         = var.python_image
  keep_locally = true
}

resource "docker_container" "pilot" {
  name         = "tcc-n20-local-${var.run_id}"
  image        = docker_image.python.image_id
  user         = "65534:65534"
  privileged   = false
  network_mode = "none"
  restart      = "no"
  must_run     = false
  rm           = false
  memory       = 256
  cpu_period   = 100000
  cpu_quota    = 100000

  security_opts = ["no-new-privileges:true"]
  capabilities {
    drop = ["ALL"]
  }

  upload {
    file        = "/tmp/tcc-payload.zip"
    source      = var.archive
    source_hash = filesha256(var.archive)
    permissions = "0644"
  }

  # No bind mount. Copy the output with docker cp after this one-shot process stops.
  command = [
    "python", "-B", "-c",
    "import runpy,sys,zipfile; zipfile.ZipFile('/tmp/tcc-payload.zip').extractall('/tmp/tcc-src'); sys.path.insert(0,'/tmp/tcc-src'); runpy.run_path('/tmp/tcc-src/pilot.py',run_name='__main__')"
  ]

  labels {
    label = "org.tcc.purpose"
    value = "terraform-local-cpu-mock"
  }

  labels {
    label = "org.tcc.run-id"
    value = var.run_id
  }
}

output "container_name" {
  value = docker_container.pilot.name
}
