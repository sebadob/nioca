<script>
    import {onMount} from "svelte";
    import OrderSearchBar from "$lib/search/OrderSearchBar.svelte";
    import {fetchGetGroups, fetchGetUsers} from "../../../utils/dataFetching.js";
    import UserTile from "./UserTile.svelte";

    let err = '';
    let users = [];
    let resUsers = [];
    let groups = [];

    let searchOptions = [
        {
            label: 'E-Mail',
            callback: (item, search) => item.email.includes(search.toLowerCase()),
        },
    ];
    let orderOptions = [
        {
            label: 'E-Mail',
            callback: (a, b) => a.email.localeCompare(b.email),
        },
    ];

    onMount(() => {
        fetchGroups();
        fetchUsers();
    })

    async function fetchGroups() {
        let res = await fetchGetGroups();
        if (!res.ok) {
            let body = await res.json();
            err = 'Error fetching groups: ' + body.message;
        } else {
            groups = await res.json();
        }
    }

    async function fetchUsers() {
        let res = await fetchGetUsers();
        let body = await res.json();
        if (res.ok) {
            users = body;
        } else {
            err = 'Error fetching users: ' + body.message;
        }
    }

</script>

{err}

<div class="content">
    <OrderSearchBar
            items={users}
            bind:resItems={resUsers}
            searchOptions={searchOptions}
            orderOptions={orderOptions}
    />

    {#each resUsers as user (user.id)}
        <UserTile bind:groups bind:user />
    {/each}

    <div style="height: 20px"></div>
</div>
