# This file should be placed in nixpkgs at:
# pkgs/by-name/bt/btblocker/package.nix
#
# Follow the guide at: https://github.com/NixOS/nixpkgs/blob/master/pkgs/README.md

{ lib
, buildGoModule
, fetchFromGitHub
, pkg-config
, libnetfilter_queue
, libnfnetlink
}:

buildGoModule rec {
  pname = "btblocker";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner = "spaiter";
    repo = "BitTorrentBlocker";
    rev = "v${version}"; # You'll need to create a git tag
    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; # Update this
  };

  vendorHash = "sha256-kQfQXHJHGIPiKr5AFgmYr3M2m1NRdOUby5vm1qdu13s=";

  nativeBuildInputs = [
    pkg-config
  ];

  buildInputs = [
    libnetfilter_queue
    libnfnetlink
  ];

  subPackages = [ "cmd/btblocker" ];

  ldflags = [
    "-s"
    "-w"
    "-X main.Version=${version}"
  ];

  meta = with lib; {
    description = "High-performance DPI-based BitTorrent traffic blocker for Linux";
    homepage = "https://github.com/spaiter/BitTorrentBlocker";
    changelog = "https://github.com/spaiter/BitTorrentBlocker/releases/tag/v${version}";
    license = licenses.mit;
    maintainers = with maintainers; [ ]; # Add your nixpkgs maintainer name here
    platforms = platforms.linux;
    mainProgram = "btblocker";
  };
}
