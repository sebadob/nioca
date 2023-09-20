<script>
    import IconArrowsOut from "./icons/IconArrowsOut.svelte";

    export let right = 25;
    export let top = 25;
    export let zIndex = 10;

    let moving = false;

    function onMouseDown() {
        moving = true;
    }

    function onMouseMove(e) {
        if (moving) {
            right -= e.movementX;
            top += e.movementY;
        }
    }

    function onMouseUp() {
        moving = false;
    }

</script>

<section
        style="right: {right}px; top: {top}px; z-index: {zIndex};"
        class="draggable"
>
    <div role="button" tabindex="0" class="draggable dragHandle" on:mousedown={onMouseDown}>
        <IconArrowsOut opacity={0.5} width={14}/>
    </div>
    <slot></slot>
</section>

<svelte:window
        on:mouseup={onMouseUp}
        on:mousemove={onMouseMove}
/>

<style>
    .draggable {
        user-select: none;
        position: absolute;
    }

    .dragHandle {
        margin-left: 1px;
        cursor: move;
    }
</style>
