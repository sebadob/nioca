<script>
    import {fetchGetCAsSsh, fetchGetGroups} from "../../../utils/dataFetching.js";
    import {onMount} from "svelte";
    import CaSshInit from "./CaSshInit.svelte";
    import CaSshContainer from "./CaSshContainer.svelte";

    let cas;
    let groups = [];
    let err = '';
    let isInitialized = false;

    $: if (cas && cas.casSsh.length > 0) {
        isInitialized = true;
    }

    onMount(() => {
        fetchCAs();
        fetchGroups();
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

    async function fetchGroups() {
        let res = await fetchGetGroups();
        if (!res.ok) {
            let body = await res.json();
            err = 'Error fetching groups: ' + body.message;
        } else {
            groups = await res.json();
        }
    }

</script>

{err}

<div class="container">
    {#if cas}
        {#if isInitialized}
            <CaSshContainer bind:cas={cas.casSsh} bind:groups onSave={fetchCAs}/>
        {:else}
            <CaSshInit bind:cas/>
        {/if}
    {/if}
</div>

<style>
    .container {
        display: flex;
        width: 100%;
        margin: 30px;
    }
</style>
