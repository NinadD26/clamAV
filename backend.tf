terraform {
  backend "s3" {
    bucket = "clam-av-bckt"
    key    = "Clam-Av.tfstate"
    region = "us-east-1"
  }
}
