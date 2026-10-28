# Third party notices

Everything the page and the dashboard load is served from our own origin. No
CDN, no third-party runtime request, which is both the GDPR position and the
no-runtime-dependency one.

## Phosphor Icons

- Files: inlined SVG path data in `theme.py` (`ICONS`)
- Copyright (c) 2023 Phosphor Icons
- License: MIT
- Source: npm package `@phosphor-icons/core` 2.1.1, phosphoricons.com
- Regular weight. Inlined rather than linked so each glyph inherits
  `currentColor` and costs no request, the same choice an earlier project
  of the author's made.
- Constraint carried over: never an icon that claims a verdict. No tick,
  seal, shield or padlock as a status (`docs/DESIGN.md` section 3).
- MIT covers commercial use, which is the condition set on adding these.
  Every glyph in `ICONS` comes from that one package at that one version and
  weight, so extending the set does not extend this notice.

## Vendor logos

Five channels carry their own logo: Slack, Discord, Telegram, Webhook and
Microsoft Teams. **All five are Phosphor's own drawings**, from the same package,
weight and 256 grid as every other glyph here, so there is one icon set and one
licence in the page rather than two.

Jerome named them on 2026-08-16. An earlier round had gone looking for brand
marks in another set, on the reasoning that Phosphor lacked them. It does not,
and using its own means nothing has to be reconciled: no second viewBox, no
second licence, no marks at a different optical weight.

The marks remain the property of their owners. We draw them to name the
destination a channel talks to, monochrome, inheriting `currentColor`, never
recoloured into a hue of ours, stretched, rotated or redrawn.

ntfy has no Phosphor logo, so it carries a neutral glyph with its name beside it.

`linux-logo` and `windows-logo` on the add-server cards are Phosphor's own
drawings of an operating system, not a company we integrate with.

## Fonts

- Files: `fonts/*.woff2`, shipped with `fonts/OFL.txt` as the licence requires
- Space Grotesk, Work Sans, IBM Plex Mono
- License: SIL Open Font License 1.1
- Self hosted, never loaded from Google Fonts or any CDN
  (`docs/DESIGN.md` section 1).

## Vendor marks on the Integrations screen

Thirteen marks are inlined in `theme.py` as `MARKS`. Eleven come from Simple
Icons 16.28.0 (simpleicons.org, CC0 1.0 for the set, drawn on a 24 grid):
Hetzner, DigitalOcean, Vultr, OVHcloud, Scaleway, AWS, Akamai standing for
Linode, Prometheus, Grafana, Docker and Podman. Azure's is from Simple Icons 8.15.0, the last version
that carried Microsoft's marks. Zabbix's is the monochrome wordmark from
Zabbix's own 2025 logo pack (`zabbix.com/trademark`), on its own canvas, and
"Zabbix is a registered trademark of Zabbix LLC". Each stays its owner's
trademark, drawn monochrome in `currentColor` to name what we connect to, never
recoloured, stretched or redrawn. Syslog is a protocol and has none.

**Docker and Podman joined on 2026-09-10**, with the Packet path tab, which
draws one box per tool and names the runtime that published a port (record
4.168). Read that day, from their own pages. Docker's trademark guidelines
permit "limited fair use of our Marks in naming or referring to our products,
services or technology, for example in a magazine article, without our
permission", and the same page prohibits "the preparation of derivative works
that imitate these design elements" without prior approval, which a Simple
Icons redrawing arguably is. Podman is an LF Projects project and points its
trademark policy at the LF Projects policies page rather than stating one of
its own. Both are carried on the same decision as the marks above.

**Every owner whose terms could be read wants to be asked first.** Jerome read
that on 2026-09-07 and decided to carry it: the marks stay as the sketches draw
them, and we take a mark down the day its owner asks (record 4.152). What each
owner's own page said that day, read for the question "may a third party show
our logo to say it integrates with us":

- AWS, `aws.amazon.com/trademark-guidelines`: the logo needs written permission,
  the name may be used in text as "[Your Brand] for [AWS Mark]", never implying
  affiliation, never more prominent than your own brand.
- Microsoft (Azure), `microsoft.com/en-us/legal/intellectualproperty/trademarks`:
  "our logos, app and product icons ... can never be used without an express
  license". Product names may be used in text to truthfully convey compatibility.
- The Linux Foundation (Prometheus), `linuxfoundation.org/legal/trademark-usage`:
  do not use a project logo on websites or marketing materials without written
  permission. "<product> compatible with <mark>" and "for use with" are the allowed
  forms, in text.
- Grafana Labs, `grafana.com/trademark-policy`: do not use the marks in or on any
  website without express written permission.
- DigitalOcean, `digitalocean.com/legal/trademark-usage-guidelines`: "Don't use
  DigitalOcean's logos or designs without our express written permission". In
  text, "for use with DigitalOcean" is the recommended form.
- Zabbix, `zabbix.com/trademark`: the unaltered logo is allowed for non-commercial
  use that creates no impression of an official link, and a licence is needed
  where it could. This product is commercial, so the name alone, with the line
  "Zabbix is a registered trademark of Zabbix LLC" wherever the name is used.
- Slack, `slack.com/terms-of-service/slack-brand`: "Don't use the Slack logo (with
  or without your company logo)". An app in the Slack Marketplace may say it
  integrates with Slack. The Alerts channel keeps Phosphor's drawing of the mark
  on the same decision.
- Discord, `discord.com/branding`: permission is needed "except as specifically
  permitted", and what is permitted is saying you are a Discord user or have a
  server. Integrations are not named. The Alerts channel keeps Phosphor's drawing
  on the same decision.
- Telegram, `telegram.org/press`: "If you need Telegram logos, take these", with
  one condition, "just make sure people understand you're not representing
  Telegram officially". The Alerts channel does not.
- Akamai (Linode), `akamai.com/newsroom/media-resources`: a non-press third party
  goes through the Brand Permission Request process.
- Hetzner, `hetzner.com/pressroom`: press images are copyrighted, usable with
  reference to Hetzner Online GmbH as the source, editing only with written
  consent, and use must be communicated to Hetzner's press office. Nothing about a
  third party's integration.
- OVHcloud, the trademark usage policy PDF on
  `ovhcloud.com/en/intellectual-property/trademark`: "Use of the OVHcloud
  Trademarks is prohibited unless expressly authorised per an Agreement and these
  Guidelines". A partner may use the marks to indicate the partnership, less
  prominently than its own product name.
- Scaleway and Vultr: no brand terms could be read that day. Vultr's brand page
  answered 403, Scaleway publishes none we could find.
