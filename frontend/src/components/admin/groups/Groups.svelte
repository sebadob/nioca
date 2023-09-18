<script>
    import {onMount} from "svelte";
    import OrderSearchBar from "$lib/search/OrderSearchBar.svelte";
    import {fetchGetCAsSsh, fetchGetCAsX509, fetchGetGroups} from "../../../utils/dataFetching.js";
    import GroupTile from "./GroupTile.svelte";
    import GroupsTileAddNew from "./GroupsTileAddNew.svelte";

    let msg = '';
    let groups = [];
    let resGroups = [];
    let casSsh = [];
    let casX509 = [];

    let searchOptions = [
        {
            label: 'ID',
            callback: (item, search) => item.id.includes(search.toLowerCase()),
        },
        {
            label: 'Name',
            callback: (item, search) => item.name.includes(search.toLowerCase()),
        },
    ];
    let orderOptions = [
        {
            label: 'ID',
            callback: (a, b) => a.id.localeCompare(b.id),
        },
        {
            label: 'Name',
            callback: (a, b) => a.name.localeCompare(b.name),
        },
    ];

    onMount(() => {
        fetchCAsSsh();
        fetchCAsX509();
        fetchGroups();
    })

    async function fetchCAsSsh() {
        let res = await fetchGetCAsSsh();
        let body = await res.json();
        if (res.ok) {
            if (body.casSsh.length > 0) {
                let cas = [];
                for (let ca of body.casSsh) {
                    cas.push(ca.groupName);
                }
                casSsh = cas;
            }
            casSsh = body.casSsh;
        }
    }

    async function fetchCAsX509() {
        let res = await fetchGetCAsX509();
        let body = await res.json();
        if (res.ok) {
            if (body.casX509.length > 0) {
                let cas = [];
                for (let ca of body.casX509) {
                    cas.push(ca.groupName);
                }
                casX509 = cas;
            }
            casX509 = body.casX509;
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
        fetchGroups();
    }
</script>

{msg}

<div class="content">
    <OrderSearchBar
            items={groups}
            bind:resItems={resGroups}
            searchOptions={searchOptions}
            orderOptions={orderOptions}
    />

    <GroupsTileAddNew bind:casSsh bind:casX509 onSave={onSave}/>

    {#each resGroups as group}
        <GroupTile bind:group bind:casSsh bind:casX509 onSave={onSave}/>
    {/each}

    <div style="height: 20px"></div>
</div>
