# Homebrew formula for lawctl.
#
# To use:
#   brew tap lawctl/tap
#   brew install lawctl
#
# This formula is auto-updated by the release workflow.
# Repo: https://github.com/abcxz/homebrew-tap

class Lawctl < Formula
  desc "Universal agent firewall — keeps your AI coding agent from breaking things"
  homepage "https://github.com/abcxz/lawctl"
  license "MIT"
  version "0.1.0"

  on_macos do
    on_arm do
      url "https://github.com/abcxz/lawctl/releases/download/v#{version}/lawctl-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "449681a72f4a715c06f356e7a28f4c65243c3fdd8c91398d22f5c4d3d3efe6e1"
    end

    on_intel do
      url "https://github.com/abcxz/lawctl/releases/download/v#{version}/lawctl-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "7f5b5650af0a523c291cfa89d949daea31cc07d26a3d87224f177a990d5afa80"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/abcxz/lawctl/releases/download/v#{version}/lawctl-v#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "bc538070587b1c3f8333530df21b7354e88fc39f82ef7487a30c5d8409690a72"
    end
  end

  def install
    bin.install "lawctl"
    bin.install "lawctl-hook"
    bin.install "lawctl-shim"
  end

  def post_install
    ohai "lawctl installed! Go to your project and run:"
    ohai "  lawctl"
  end

  test do
    assert_match "lawctl", shell_output("#{bin}/lawctl --version")
  end
end
