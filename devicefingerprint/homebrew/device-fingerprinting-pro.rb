class DeviceFingerprintingPro < Formula
  include Language::Python::Virtualenv

  desc "Professional-grade hardware-based device identification for Python applications"
  homepage "https://github.com/Johnsonajibi/DeviceFingerprinting"
  url "https://files.pythonhosted.org/packages/source/d/device-fingerprinting-pro/device_fingerprinting_pro-1.0.3.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256"
  license "MIT"

  depends_on "python@3.11"

  resource "cryptography" do
    url "https://files.pythonhosted.org/packages/source/c/cryptography/cryptography-41.0.0.tar.gz"
    sha256 "REPLACE_WITH_ACTUAL_SHA256"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/python", "-c", "from devicefingerprint import generate_device_fingerprint; print('Test passed')"
  end
end
