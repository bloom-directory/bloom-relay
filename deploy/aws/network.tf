data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 2)
}

resource "aws_vpc" "relay" {
  cidr_block                       = var.vpc_cidr
  enable_dns_support               = true
  enable_dns_hostnames             = true
  assign_generated_ipv6_cidr_block = true

  tags = { Name = "bloom-relay-${var.placement}" }
}

resource "aws_internet_gateway" "relay" {
  vpc_id = aws_vpc.relay.id
}

# The relay host lives in the first public subnet. No NAT gateway: the
# database needs no egress, and the host reaches AWS APIs through its
# public addresses.
resource "aws_subnet" "public" {
  count = 2

  vpc_id                          = aws_vpc.relay.id
  availability_zone               = local.azs[count.index]
  cidr_block                      = cidrsubnet(var.vpc_cidr, 8, count.index)
  ipv6_cidr_block                 = cidrsubnet(aws_vpc.relay.ipv6_cidr_block, 8, count.index)
  assign_ipv6_address_on_creation = true

  tags = { Name = "bloom-relay-public-${local.azs[count.index]}" }
}

# RDS Multi-AZ needs subnets in two zones. These have no internet route.
resource "aws_subnet" "database" {
  count = 2

  vpc_id            = aws_vpc.relay.id
  availability_zone = local.azs[count.index]
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 10 + count.index)

  tags = { Name = "bloom-relay-database-${local.azs[count.index]}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.relay.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.relay.id
  }

  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.relay.id
  }
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "relay_host" {
  name        = "bloom-relay-host-${var.placement}"
  description = "Relay control and Browser ingress"
  vpc_id      = aws_vpc.relay.id
}

# Both public addresses serve 443: HAProxy on the control address, the
# gateway on the Browser ingress address.
resource "aws_vpc_security_group_ingress_rule" "https_v4" {
  security_group_id = aws_security_group.relay_host.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "https_v6" {
  security_group_id = aws_security_group.relay_host.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# Certbot renews the control certificate with standalone HTTP-01; nothing
# listens on 80 outside a renewal.
resource "aws_vpc_security_group_ingress_rule" "acme_http_v4" {
  security_group_id = aws_security_group.relay_host.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each = toset(var.admin_ssh_cidrs)

  security_group_id = aws_security_group.relay_host.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}

resource "aws_vpc_security_group_egress_rule" "all_v4" {
  security_group_id = aws_security_group.relay_host.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_vpc_security_group_egress_rule" "all_v6" {
  security_group_id = aws_security_group.relay_host.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "database" {
  name        = "bloom-relay-database-${var.placement}"
  description = "PostgreSQL from the relay host only"
  vpc_id      = aws_vpc.relay.id
}

resource "aws_vpc_security_group_ingress_rule" "postgres_from_relay" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.relay_host.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}
