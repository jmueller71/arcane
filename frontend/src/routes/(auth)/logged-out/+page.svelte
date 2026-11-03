<script lang="ts">
	import OidcStatusPanel from '#lib/components/oidc-status-panel.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { m } from '#lib/paraglide/messages.js';
</script>

<svelte:head><title>{m.layout_title()}</title></svelte:head>

<!-- Return target after provider logout; never redirects on its own so the provider is not re-entered. -->
<OidcStatusPanel busy={false} busyTitle="" busyDescription="" error="">
	<h2 class="text-2xl font-semibold">{m.auth_signed_out_title()}</h2>
	<p class="mt-2 text-sm text-muted-foreground">{m.auth_signed_out_description()}</p>
	<Button class="mt-6" href="/login">{m.auth_sign_in_again()}</Button>
</OidcStatusPanel>
