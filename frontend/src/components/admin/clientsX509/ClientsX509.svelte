<script>
    import {onMount} from "svelte";
    import ClientTile from "./ClientTile.svelte";
    import ClientTileAddNew from "./ClientTileAddNew.svelte";
    import OrderSearchBar from "$lib/search/OrderSearchBar.svelte";
    import {fetchGetGroups, fetchGetClientsX509} from "../../../utils/dataFetching.js";

    let msg = '';
    let clients = [];
    let resClients = [];
    let groups = [];

    let searchOptions = [
        {
            label: 'ID',
            callback: (item, search) => item.id.includes(search.toLowerCase()),
        },
    ];
    let orderOptions = [
        {
            label: 'ID',
            callback: (a, b) => a.id.localeCompare(b.id),
        },
    ];

    onMount(async () => {
        fetchClients();
        fetchGroups();
    })

    async function fetchClients() {
        let res = await fetchGetClientsX509();
        if (!res.ok) {
            let body = await res.json();
            msg = 'Error fetching clients: ' + body.message;
        } else {
            let c = await res.json();
            clients = [...c];
        }
    }

    async function fetchGroups() {
        let res = await fetchGetGroups();
        if (!res.ok) {
            let body = await res.json();
            msg = 'Error fetching groups: ' + body.message;
        } else {
            groups = await res.json();
        }
    }

    function onSave() {
        fetchClients();
    }
</script>

{msg}

<div class="content">
    <OrderSearchBar
            items={clients}
            bind:resItems={resClients}
            searchOptions={searchOptions}
            orderOptions={orderOptions}
    />

    <ClientTileAddNew bind:groups onSave={onSave}/>

    {#each resClients as client (client.id)}
        <ClientTile bind:groups bind:client onSave={onSave}/>
    {/each}

    <div style="height: 20px"></div>
</div>
