# Maintainer: ron <you@example.com>
pkgname=sonarch
pkgver=0.1.0
pkgrel=1
pkgdesc='Predict shared-library (soname) breakage before running pacman -Syu'
arch=('any')
url='https://github.com/zxc2077x/sonarch'
license=('MIT')
depends=('python' 'pacman' 'fakeroot')
optdepends=('zstd: fallback for reading zstd-compressed sync databases')
checkdepends=('gcc')
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')  # run `updpkgsums` to replace this before pushing

check() {
  cd "$pkgname-$pkgver"
  python -m unittest test_sonarch
}

package() {
  cd "$pkgname-$pkgver"
  install -Dm755 sonarch.py "$pkgdir/usr/bin/sonarch"
  install -Dm644 LICENSE -t "$pkgdir/usr/share/licenses/$pkgname/"
  install -Dm644 README.md -t "$pkgdir/usr/share/doc/$pkgname/"
}
