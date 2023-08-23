<script>
    export let ca;
</script>

<div class="container">
    <div class="top">
        <div><b>{ca.name}</b></div>
        <div class="font-mono">{ca.id}</div>
    </div>

    <div class="pubKey">
        <div class="font-mono">
            <code>
                {ca.pubKey}
            </code>
        </div>
    </div>
</div>

<style>
    .container {
        height: 75px;
        display: flex;
        flex-direction: column;
        border: 1px solid var(--col-inact);
        padding: 10px
    }

    .pubKey {
        margin-top: 5px;
    }

    .top {
        display: flex;
        justify-content: space-between;
    }
</style>
