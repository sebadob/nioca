<script>
    import {fetchGetCAsX509Inspect, fetchGetGroups} from "../../../utils/dataFetching.js";
    import {onMount} from "svelte";
    import CaX509Tile from "./CaX509Tile.svelte";
    import CaX509AddNew from "./CaX509AddNew.svelte";

    let cas = [];
    let groups = [];
    let err = '';

    onMount(() => {
        fetchCAs();
        fetchGroups();
    });

    async function fetchCAs() {
        let res = await fetchGetCAsX509Inspect();
        let body = await res.json();
        if (res.ok) {
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

    <CaX509AddNew onSave={fetchCAs}/>

    {#each Object.values(cas) as ca (ca.root.id)}
        <CaX509Tile bind:ca bind:groups onSave={fetchCAs}/>
    {/each}
</div>

<style>
    .container {
        display: flex;
        flex-direction: column;
        flex: 1;
        width: 100%;
        margin: 30px;
    }
</style>
