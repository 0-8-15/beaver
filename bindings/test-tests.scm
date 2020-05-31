#;(test-assert
 ""
 #t)

;; (test-error msg expr)

;; (test-condition msg expr pred)

(test-assert "trivial true" #t)
(test-error "trivial error" (raise #t))
(test-condition "trivial caught condition" (raise 'nix) (lambda (x) (eq? x 'nix)))
