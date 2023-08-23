<script>
    import ExpandContainer from "$lib/ExpandContainer.svelte";
    import Tooltip from "$lib/Tooltip.svelte";
    import TabBar from "$lib/TabBar.svelte";
    import {slide} from 'svelte/transition';
    import ClientConfig from "./ClientConfig.svelte";
    import ClientSecret from "./ClientSecret.svelte";
    import ClientDelete from "./ClientDelete.svelte";
    import ClientCertificate from "./ClientCertificate.svelte";

    export let groups = [];
    export let client = {};
    export let onSave;

    let expandContainer;

    const tabBarItems = [
        'Config',
        'Secret',
        'Certificate',
        'Delete',
    ];
    let selected = tabBarItems[0];
    const tabBarDly = 250;
    const tabBarDur = 200;

    function onDelete() {
        expandContainer = false;
        onSave();
    }

</script>

<ExpandContainer bind:show={expandContainer}>
    <div class="header" slot="header">
        <Tooltip text="Client ID">
            <div class="data font-mono">
                {client.id}
            </div>
        </Tooltip>

        {#if client.name}
            <Tooltip text="Client Name">
                <div class="data">
                    {client.name}
                </div>
            </Tooltip>
        {/if}
    </div>

    <div slot="body">
        <TabBar labels={tabBarItems} bind:selected/>

        {#if selected === 'Config'}
            <div in:slide|global={{ delay: tabBarDly, duration: tabBarDur }} out:slide|global>
                <ClientConfig bind:groups bind:client bind:onSave/>
            </div>

        {:else if selected === 'Secret'}
            <div in:slide|global={{ delay: tabBarDly, duration: tabBarDur }} out:slide|global>
                <ClientSecret bind:client/>
            </div>

        {:else if selected === 'Certificate'}
            <div in:slide|global={{ delay: tabBarDly, duration: tabBarDur }} out:slide|global>
                <ClientCertificate bind:client/>
            </div>

        {:else if selected === 'Delete'}
            <div in:slide|global={{ delay: tabBarDly, duration: tabBarDur }} out:slide|global>
                <ClientDelete bind:client onSave={onDelete}/>
            </div>
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
