<script>
    import {onMount} from "svelte";
    import {fetchUnsealStatus} from "../../utils/dataFetchingUnseal.js";
    import Init from "../../components/unseal/Init.svelte";
    import Unseal from "../../components/unseal/Unseal.svelte";

    let status;
    let err = '';

    onMount(() => {
        getStatus();
    });

    async function getStatus() {
        let res = await fetchUnsealStatus();
        let body = await res.json();

        if (res.ok) {
            status = body;
        } else {
            err = body.msg;
        }
    }
</script>

{#if err}
    <div style="color: var(--col-err)">
        {err}
    </div>
{/if}

{#if status}
    {#if status.isInitialized}
        <Unseal/>
    {:else}
        <Init/>
    {/if}
{/if}
