# PR plan and status

Twenty-three stages, built in order. Each stage was a pull request with a branch named `prNN-name`, a title `PR NN: Title [PPS-xx]`, passing CI, and an approving review by the repository owner before merging. The stage number is **not** the GitHub pull-request number; the table gives both.

Jira project `PPS`. Some early PRs used SRS IDs (such as `PPS-F-001`) in place of Jira keys, so Jira did not link them. Later PRs use the keys from the team plan.

## Stages

| Stage | Title | Owner | Jira | GitHub PR | Merged (UTC) | Status |
|---|---|---|---|---|---|---|
| 01 | Repository setup | Mebin | — | #1 | 29 Oct 2026 | Merged |
| 02 | CI workflows | Mebin | — | #3 (#2 merged into a branch, so re-raised as #3) | 30 Oct 2026 | Merged |
| 03 | DNS and HTTP labelling | Mayukh | PPS-19 | #5, #6 (#4 closed as a duplicate) | 30 Oct 2026 | Merged |
| 04 | Packet decoder | Nakul | PPS-18 | #7 | 2 Nov 2026 | Merged |
| 05 | Decoder replay tests on demo PCAPs | Mayukh | PPS-23 | #8 | 3 Nov 2026 | Merged |
| 06 | Display filters and Boolean logic | Mayukh | PPS-26, PPS-27 | #9 | 3 Nov 2026 | Merged |
| 07 | Storage, rotation and audit chain | Mayukh | PPS-20, PPS-30 ¹ | #10 | 5 Nov 2026 | Merged |
| 07b | Storage follow-up: settings paths and review fixes | Mayukh | PPS-20, PPS-30 | #11 | 5 Nov 2026 | Merged |
| 08 | Capture interfaces and monitor mode | Mebin | PPS-15 | #12 | 6 Nov 2026 | Merged |
| 09 | ARP spoofing and port-scan detectors | Nakul | PPS-31, PPS-32 | #13 | 7 Nov 2026 | Merged |
| 10 | Accounts, roles and pairing | Mebin | PPS-35 | #14 | 7 Nov 2026 | Merged |
| 11 | Capture engine | Nakul | PPS-16 | #15 | 7 Nov 2026 | Merged |
| 11b | Core wiring for the auth service | Nia | PPS-16 | #16 | 8 Nov 2026 | Merged |
| 12 | API backend and live WebSocket | Nia | PPS-34, PPS-21 | #17 | 10 Nov 2026 | Merged |
| 13 | Dashboard and live capture tab | Nia | PPS-22, PPS-17 | #18 | 10 Nov 2026 | Merged |
| 14 | Filter validation and presets API | Mayukh | PPS-25, PPS-28 | #19 | 10 Nov 2026 | Merged |
| 15 | Sessions tab and PCAP download | Nia | PPS-29 | #20 | 10 Nov 2026 | Merged |
| 16 | Alerts | Nia | PPS-33 | #21 | 11 Nov 2026 | Merged |
| 17 | HTTPS | Mebin | PPS-37 | #22 | 11 Nov 2026 | Merged |
| 18 | Settings page | Nia | PPS-38 | #23 | 11 Nov 2026 | Merged |
| 19 | Users and audit log | Mebin | PPS-36 | #24 | 11 Nov 2026 | Merged |
| 20 | Device health view | Nakul | PPS-39 | #26 (#25 closed as a duplicate) | 13 Nov 2026 | Merged |
| 21 | Module boundary contracts (import-linter) | Mayukh | PPS-40 | #27 | 14 Nov 2026 | Merged |
| 22 | Performance benchmark and test report | Nakul | PPS-41 | #28 | 16 Nov 2026 | Merged |
| 23 | Deviations log and final documentation | Mebin | PPS-42, PPS-43 | this PR | — | In review |

¹ The title of PR #10 used the keys PPS-30, PPS-32 and PPS-34. PPS-32 and PPS-34 belong to other stages, so the card mapping in this table uses PPS-20 and PPS-30 instead.

## Schedule

The project timetable was Sprint 1 from 19 to 23 October 2026 and Sprint 2 from 26 to 30 October 2026, with the sprint 2 freeze at the end of sprint 2. The first stage merged on 29 October, and the last content stage on 16 November. Only stages 01 to 03 merged by the end of Sprint 2; the rest merged between 2 and 16 November. The planned and actual dates are both recorded here and nothing in the repository history has been backdated. See D20 in `docs/DEVIATIONS.md`.

## Process notes

- **Stacked PR, stage 02.** It was based on the branch of stage 01 and merged into it rather than into `main`, so it did not reach `main`. It was re-raised against `main` as #3.
- **Shared checkout, stage 17.** Two working sessions wrote to the same checkout and overwrote uncommitted files. The work was consolidated onto one branch before the PR was raised.
- **History rewrite, 30 October.** `main` was force-pushed twice on the same day to correct commit attribution, including commits by Mebin and one commit by Nia. File contents did not change, but the commit hashes did.
- **Jira keys.** Stages 08 and 10 used SRS IDs in their titles and did not link to Jira. The Jira keys in this table are the ones used for those stages going forward.

## Open items at this point

- Stage 23 (this PR) is the last stage. Its items are a deviations log, final documentation and a development freeze checklist.
- The Sprint 1 demonstration video is not recorded. It was planned for after stage 13.
- The Sprint 2 demonstration video is not recorded.
- The release tag `v1.0` has not been created.
- The SAD is not in the repository.
- Branch protection on `main` requires checking in GitHub settings.
