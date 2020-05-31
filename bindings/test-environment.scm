
(define test-hook '())
(define (add-test! thunk)
  (set! test-hook (cons thunk test-hook)))

(define test-results (vector 0 0 0))

(define (test-stats+! idx) (vector-set! test-results idx (+ (vector-ref test-results idx) 1)))

(define (tests-begin)
  (set! test-hook '())
  (set! test-results (vector 0 0 0)))

(define (tests-end)
  (define (X idx) (vector-ref test-results idx))
  (let ((tbd (reverse test-hook)))
    (for-each (lambda (t) (t)) tbd))
  (for-each display (list "TOTAL " (X 0) " PASS " (X 1) " FAIL " (X 2) "\n"))
  (tests-begin))

;; (define (add-test! thunk) (thunk))

(define (test-report-begin msg)
  (test-stats+! 0)
  (display "Test ") (display msg) (display ": ")
  (real-time))

(define (test-report-pass2 t0 t1 result)
  (test-stats+! 1)
  (println "\n  PASS " (- t1 t0) "''\n"))

(define (test-report-pass t0 result) (test-report-pass2 t0 (real-time) result))

(define (test-report-expected-condition t0 result)
  (let ((t1 (real-time)))
    (display result)
    (test-report-pass2 t0 t1 result)))

(define (test-report-make-expected-condition pred?)
  (lambda (t0 exn)
    (if (pred? exn) (test-report-pass t0 exn) (test-report-fail t0 exn))))

(define (test-report-fail t0 result)
  (define t1 (real-time))
  (test-stats+! 2)
  (if (error-exception? result)
      (begin
        (display (error-exception-message result))
        (display " ")
        (display (error-exception-parameters result)))
      (display result))
  (println "  FAIL " (- t1 t0) "''\n"))

(define (test-thunk msg thunk success fail condition)
  (lambda ()
    (let* ((t0 0)
           (on-exn (lambda (exn) (condition t0 exn)))
           (run (lambda ()
                  (let ((tmp #f))
                    (set! t0 (test-report-begin msg))
                    (set! tmp (thunk))
                    (if tmp (test-report-pass t0 tmp) (test-report-fail t0 tmp))))))
      (with-exception-catcher on-exn run))))

(define-macro/rt (test-assert msg expr)
  `(add-test! (test-thunk ,msg (lambda () ,expr) test-report-pass test-report-fail test-report-fail)))

(define-macro/rt (test-error msg expr)
  `(add-test! (test-thunk ,msg (lambda () ,expr) test-report-fail test-report-fail test-report-expected-condition)))

(define-macro/rt (test-condition msg expr pred)
  `(add-test!
    (test-thunk
     ,msg (lambda () ,expr) test-report-fail test-report-fail
     (test-report-make-expected-condition ,pred))))
