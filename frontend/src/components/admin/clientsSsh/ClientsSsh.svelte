<script>
    import {onMount} from "svelte";
    import ClientTile from "./ClientTile.svelte";
    import ClientTileAddNew from "./ClientTileAddNew.svelte";
    import OrderSearchBar from "$lib/search/OrderSearchBar.svelte";
    import {fetchGetCAsSsh, fetchGetClientsSsh, fetchGetGroups} from "../../../utils/dataFetching.js";

    let msg = '';
    let clients = [];
    let resClients = [];
    let groups;

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
        fetchGroups();
        fetchClients();
    })

    async function fetchGroups() {
        let res = await fetchGetGroups();
        if (!res.ok) {
            let body = await res.json();
            msg = 'Error fetching groups: ' + body.message;
        } else {
            groups = await res.json();
        }
    }

    async function fetchClients() {
        let res = await fetchGetClientsSsh();
        if (!res.ok) {
            let body = await res.json();
            msg = 'Error fetching clients: ' + body.message;
        } else {
            let c = await res.json();
            clients = [...c];
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
        <ClientTile bind:client bind:groups onSave={onSave}/>
    {/each}

    <div style="height: 20px"></div>
</div>
