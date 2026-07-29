; SPDX-License-Identifier: MPL-2.0
;; guix.scm — GNU Guix package definition for php-aegis
;; Usage: guix shell -f guix.scm

(use-modules (guix packages)
             (guix build-system gnu)
             (guix licenses))

(package
  (name "php-aegis")
  (version "0.1.0")
  (source #f)
  (build-system gnu-build-system)
  (synopsis "php-aegis")
  (description "php-aegis — part of the hyperpolymath ecosystem.")
  (home-page "https://github.com/hyperpolymath/php-aegis")
  (license mpl2.0))
