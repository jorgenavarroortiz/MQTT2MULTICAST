echo "======= S1 flows ======="
sudo ovs-ofctl dump-flows s1 -OOpenFlow13
echo "======= S2 flows ======="
sudo ovs-ofctl dump-flows s2 -OOpenFlow13
echo "======= S3 flows ======="
sudo ovs-ofctl dump-flows s3 -OOpenFlow13
