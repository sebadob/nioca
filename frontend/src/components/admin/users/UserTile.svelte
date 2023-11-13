<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import { fetchGetUserAccess } from "../../../utils/dataFetching";
    import UserConfig from "./UserConfig.svelte";

    export let groups = [];
    export let user = {};

    let expandContainer;
    let accessGroups;

    $: if (expandContainer) {
        getAccessGroups();
    }

    async function getAccessGroups() {
        let res = await fetchGetUserAccess(user.id);
        let body = await res.json();
        if (res.ok) {
            accessGroups = body;
        } else {
            console.error(body.message);
        }
    }

    async function onSave() {
        await getAccessGroups();
    }

</script>

<ExpandContainer bind:show={expandContainer}>
    <div class="header" slot="header">
        <div class="data">
            {user.email}
        </div>

        <div class="data">
            {`${user.givenName} ${user.familyName}`}
        </div>
    </div>

    <div slot="body">
        {#if accessGroups}
            <UserConfig bind:user bind:accessGroups bind:groups onSave={onSave} />
        {/if}
    </div>
</ExpandContainer>

<style>
    .data {
        display: flex;
        align-items: center;
        margin: 3px 10px;
    }

    .header {
        display: flex;
        align-items: center;
    }
</style>
