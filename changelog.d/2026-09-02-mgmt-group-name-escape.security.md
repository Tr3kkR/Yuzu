- **Fixed a stored-XSS vulnerability in the Settings management-groups fragment.** A management
  group's `name` (and `id`) was rendered unescaped in three places — the group list, the delete
  button's `hx-confirm` attribute, and the "Create group" parent dropdown — so any principal able
  to create a management group could plant markup that executed in an Administrator's Settings
  session. All render sites now escape via `html_escape()`.
