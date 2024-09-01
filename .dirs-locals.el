;;; .dirs-locals.el --- Description -*- lexical-binding: t; -*-
;;
;; Copyright (C) 2024 MDBDEVIO
;;
;; Author: MDBDEVIO <martin@Lok>
;; Maintainer: MDBDEVIO <martin@Lok>
;; Created: August 30, 2024
;; Modified: August 30, 2024
;; Version: 0.0.1
;; Keywords: abbrev bib c calendar comm convenience data docs emulations extensions faces files frames games hardware help hypermedia i18n internal languages lisp local maint mail matching mouse multimedia news outlines processes terminals tex tools unix vc wp
;; Homepage: https://github.com/martin/.dirs-locals
;; Package-Requires: ((emacs "24.3"))
;;
;; This file is not part of GNU Emacs.
;;
;;; Commentary:
;;
;;  Description
;;
;;; Code:
;;;
(("content-org/"
  . ((org-mode . ((eval . (org-hugo-auto-export-mode)))))))
(use-package citeproc-org
  ensure t
  after ox-hugo
  config
  (citeproc-org-setup))



;;(provide '.dirs-locals)
;;; .dirs-locals.el ends here
