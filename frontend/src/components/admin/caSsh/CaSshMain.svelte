<script>
    import {fetchGetCAsSsh} from "../../../utils/dataFetching.js";
    import {onMount} from "svelte";
    import CaSshInit from "./CaSshInit.svelte";
    import CaSshContainer from "./CaSshContainer.svelte";

    let cas;
    let err = '';
    let isInitialized = false;

    $: if (cas && cas.casSsh.length > 0) {
        isInitialized = true;
    }

    onMount(() => {
        fetchCAs();
    });

    async function fetchCAs() {
        let res = await fetchGetCAsSsh();
        let body = await res.json();
        if (res.ok) {
            if (body.casSsh.length > 0) {
                isInitialized = true;
            }
            cas = body;
        } else {
            err = body.message;
        }
    }

</script>

{err}

<div class="container">
    {#if cas}
        {#if isInitialized}
            <CaSshContainer bind:cas={cas.casSsh}/>
        {:else}
            <CaSshInit bind:cas/>
        {/if}
    {/if}
</div>

<style>
    .container {
        display: flex;
        flex: 1;
        width: 100%;
        margin: 30px;
    }
</style>
