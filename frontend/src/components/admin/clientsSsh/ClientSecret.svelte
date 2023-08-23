<script>
    import {onMount} from "svelte";
    import Button from "$lib/Button.svelte";
    import HiddenValue from "../../HiddenValue.svelte";
    import {
        fetchGetClientSshSecret,
        fetchPutClientSshSecret,
    } from "../../../utils/dataFetching.js";

    export let client;

    let err = '';
    let secret = '';

    onMount(() => {
        fetchSecret();
    });

    async function fetchSecret() {
        let res = await fetchGetClientSshSecret(client.id);

        let body = await res.json();
        if (!res.ok) {
            err = body.message;
        } else {
            secret = body.secret;
        }
    }

    async function generateSecret() {
        let res = await fetchPutClientSshSecret(client.id);
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
            <HiddenValue bind:value={secret}/>
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
        margin: 20px 10px 10px 10px;
    }

    .err {
        margin: 10px;
        color: var(--col-err);
    }

    .label {
        min-height: 30px;
        width: 135px;
        margin: 0 5px;
        display: flex;
        align-items: center;
        font-weight: bold;
    }
</style>
