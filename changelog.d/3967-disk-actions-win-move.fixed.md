- Gave the Windows `disk_actions` device-handle owner a move constructor so the
  drive-probe factory can return it by value; the deleted copy constructor had
  suppressed the implicit move and the Windows leg did not compile.
