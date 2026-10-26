# Studio table review follow-up

Apply the two deferred minor findings from PR #30, now authorized by the user's
continuation. Base 4413e113165e9eb6dbed04ae5d9448d89318e0da. Use executing-plans
inline and one final fresh review. Scope: Studio UI only; leave engine, runner,
raw gate and the separate live feth worktree untouched.

## Task 1

- Add a headless regression around exact 30px row boundaries, using the real
  ListView content viewport. Assert page distance and full visibility of the
  focused row. Use visible-height for both paging and bottom-edge scrolling.
- Add a regression proving an unchanged summary does not even borrow the table.
  Invalidate summary with the existing model-change notification, covering
  selection, sorting, filtering, results, enrichment and history replacement.
  One refresh after a batch of changes; idle/progress-only ticks are constant-time.
- Test invalidation and real headless UI updates, then run cargo xtask test.
- Record evidence, obtain fresh review, and merge only the exact green CI head.

## Review focus

Check every production table mutation invalidates summary; history clear must
clear focus/counts and enrichment must refresh details/filter membership. Check
page boundaries and bottom scrolling across styles, narrow windows and resizing.
Headless tests are not native clipboard, IME, accessibility or network evidence.
