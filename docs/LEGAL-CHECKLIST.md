# Legal protection without a lawyer

I am not a lawyer, and this is not legal advice. It is the free work that lowers your risk the most.
When money allows, pay a local lawyer for one hour to read the Terms and this list. Until then:

## 1. Make the pages truthful (this matters more than any wording)
- [ ] `.env` has `FLAWRADAR_LEGAL_ENTITY`, `FLAWRADAR_LEGAL_EMAIL`, `FLAWRADAR_LEGAL_ADDRESS`, `FLAWRADAR_LEGAL_LAW`. Use your real name or business name and a real mailbox you read.
- [ ] Every statement on /privacy matches what the code does. Check these: what is stored (reports, how long, the retention days setting), that no cookies are set, that source code is analysed in the browser, that only package names reach the server for the CVE lookup, and that the translator is built in and sends nothing to Google (after the change).
- [ ] If you ever add analytics, email sending, or any third party, update the Privacy page the same day.

## 2. Keep the safeguards that already protect you (do not remove them)
- [ ] The terms checkbox before every scan, with the version recorded.
- [ ] Ownership proof before deep scans and watches.
- [ ] Rate limits, private-address blocking, and the opt-out list (`FLAWRADAR_BLOCKED_HOSTS`).
- [ ] Nothing that exploits anything. FlawRadar reads and requests. Do not add exploit code.

## 3. Be ready for complaints
- [ ] A working mailbox on the Acceptable Use page for site owners. Check it weekly.
- [ ] A rule you follow: when a site owner asks to be excluded, add the host to `FLAWRADAR_BLOCKED_HOSTS` within a day and reply that it is done. Keep the email.
- [ ] A one-paragraph reply you can send, in `docs/abuse-reply.txt`.
- [ ] Keep logs of scans to show who accepted what terms, for the retention time the Privacy page states, and no longer.

## 4. Protect yourself personally
- [ ] Register FlawRadar as a business when you can. In Ethiopia, ask the Trade Office about the cheapest registration. A registered entity can limit personal liability. Until then you are personally the operator.
- [ ] Add "no warranty, limited liability" to the Terms (it is already there). Do not claim "guaranteed", "complete", or "secure". The site says reports are information, not a guarantee. Keep that wording.
- [ ] Do not scan sites you do not own for your own testing, except ones that invite it (the calibration list does this).

## 5. Free help to find
- A law school legal clinic, a local bar association's free-advice day, or a startup founder community that has a lawyer on call.
- Ask them to read only: the Terms, the Acceptable Use page, and the opt-out procedure. That is under an hour.
