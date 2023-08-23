<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import Tooltip from "$lib/Tooltip.svelte";
    import GroupConfig from "./GroupConfig.svelte";

    export let group = {};
    export let casSsh = [];
    export let casX509 = [];
    export let onSave;

    let expandContainer;

    // function onDelete() {
    //     expandContainer = false;
    //     onSave();
    // }

</script>

<ExpandContainer bind:show={expandContainer}>
    <div class="header" slot="header">
        <Tooltip text="Group ID">
            <div class="data font-mono">
                {group.id}
            </div>
        </Tooltip>

        <Tooltip text="Group Name">
            <div class="data">
                {group.name}
            </div>
        </Tooltip>
    </div>

    <div slot="body">
        <!--        <TabBar labels={tabBarItems} bind:selected/>-->

        <!--{#if selected === 'Config'}-->
        <!--            <div in:slide|global={{ delay: tabBarDly, duration: tabBarDur }} out:slide|global>-->
        <GroupConfig bind:group bind:casSsh bind:casX509 bind:onSave/>
        <!--            </div>-->

        <!--{:else if selected === 'Delete'}-->
        <!--    <div in:slide|global={{ delay: tabBarDly, duration: tabBarDur }} out:slide|global>-->
        <!--        <ClientDelete bind:client onSave={onDelete}/>-->
        <!--    </div>-->
        <!--{/if}-->
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
