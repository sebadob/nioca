<script>
  import { onMount } from "svelte";
  import Button from "$lib/Button.svelte";
  import HiddenValue from "../../HiddenValue.svelte";
  import { fetchGetClientX509Secret, fetchPutClientX509Secret } from "../../../utils/dataFetching.js";

  export let client;

	let err = '';
	let secret = '';

  onMount(() => {
		fetchSecret();
  });

	async function fetchSecret() {
		let res = await fetchGetClientX509Secret(client.id);

		let body = await res.json();
		if (!res.ok) {
			err = body.message;
    } else {
			secret = body.secret;
    }
  }

	async function generateSecret() {
		let res = await fetchPutClientX509Secret(client.id);
		secret = '';

		let body = await res.json();
		if (!res.ok) {
			err = body.message;
		} else {
			secret = body.secret;
		}
  }

</script>

<div class="err">
  {err}
</div>

<div class="data">
  <div class="label">
    Client Secret:
  </div>

  <div class="value font-mono">
    {#if secret}
      <HiddenValue bind:value={secret} />
    {/if}
  </div>
</div>

<div class="btn">
  <Button on:click={generateSecret}>NEW SECRET</Button>
</div>

<style>
    .btn {
      margin: 0 0 15px 7px;
    }

    .data {
        display: flex;
        align-items: center;
      margin: 20px 10px 10px 15px;
    }

    .err {
        margin: 10px;
        color: var(--col-err);
    }

    .label {
        min-height: 30px;
        width: 135px;
        display: flex;
        align-items: center;
        font-weight: bold;
    }
</style>
