<script>
    import {onMount} from "svelte";
    import Loading from "$lib/Loading.svelte";
    import {fetchStatus} from "../utils/dataFetching.js";

    let status;
    let err = '';
    let isLoading = true;

    onMount(() => {
        getStatus();
    });

    async function getStatus() {
        let res = await fetchStatus();
        let body = await res.json();

        if (res.ok) {
            status = body;
            if (body.isSealed) {
                window.location.href = '/unseal.html';
            }
        } else {
            err = body.msg;
        }

        isLoading = false;
    }
</script>

{#if isLoading}
    <Loading/>
{/if}

{#if err}
    <div style="color: var(--col-err)">
        {err}
    </div>
{/if}

{#if status && status.isInitialized}
    <slot></slot>
{/if}
