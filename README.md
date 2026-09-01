# Decky Plugins Extended

Get newer versions of Decky plugins without waiting for them to reach the
official Decky store.

Decky Plugins Extended checks the original GitHub pages for plugins in the
official store. When a plugin author publishes a newer version, this store can
offer it before the official store does. It also includes selected plugins that
are not in the official store at all.

## What this store gives you

- **Newer plugin versions.** Update sooner when a plugin author has released a
  version that the official store does not have yet.
- **More plugins.** Browse selected plugins that are not available in the
  official store.
- **The familiar Decky store.** Everything appears in the normal Decky store
  screen. The newest version is shown first.
- **Checks before publishing.** Versions added by this project are scanned for
  common security problems. No automated scan can guarantee that a plugin is
  safe, so install only plugins you trust.

## Add the store to Decky Loader

1. Open the **Quick Access Menu** on your Steam Deck.
2. Select the **Decky Loader** plug icon.
3. Open **Settings** with the gear icon.
4. Open the **General** tab.
5. Set **Store Channel** to **Custom**.
6. Set **Custom Store** to:

   ```text
   https://decky-extended-plugins.beallio.com/plugins.json
   ```

7. Return to the Decky Store with the shopping bag icon.

The store will now show the extended plugin list.

## How to spot a newer version

When this store has a newer version than the official store, the plugin
description starts with a note like this:

```text
Official store has 0.9.0; this store has 0.15.0.
```

Open the version menu to choose the release you want. The newest release is
first.

If both stores have the same version, Decky Plugins Extended uses the official
store's file. It only provides its own file when that version is not available
from the official store.

## Catalog links

You can open the plugin lists in a browser:

- [Stable plugins](https://decky-extended-plugins.beallio.com/plugins.json)
- [Testing plugins](https://decky-extended-plugins.beallio.com/testing_plugins.json)

The `decky-plugins-extended.pages.dev` addresses serve the same plugin lists.

## For developers

See [Developer.md](Developer.md) for local setup, plugin submission rules,
automation, version handling, and security-audit details.
