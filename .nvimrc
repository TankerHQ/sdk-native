let g:clang_format_path='clang-format-13'
function! Formatonsave()
  "let l:formatdiff = 0
  let l:lines = 'all'
  py3f ~/.vim/clang-format.py
endfunction
autocmd BufWritePre *.h,*.cc,*.cpp,*.hpp,*.c call Formatonsave()
