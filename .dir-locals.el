((nil . ((eval . (progn
                       (let ((project-venv-path (concat (projectile-project-root) ".venv")))
                         (when (file-directory-p project-venv-path)
                           (pyvenv-activate project-venv-path))))))))
